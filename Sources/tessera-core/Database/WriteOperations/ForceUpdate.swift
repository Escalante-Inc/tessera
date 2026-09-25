import Logging
import Foundation
import NIO
import RAW
import RAW_dh25519
import RAW_ed25519
import RAW_base64
import bedrock
import QuickLMDB
import nostr_kit_swift

extension TesseraDB {
	/// Replaces a stored event with a rewritten one, keeping every index in sync.
	///
	/// The rewritten event carries a fresh id/date (its content was re-signed), so it is stored
	/// under a *new* key and the original event is removed. Failing to do both leaves the old
	/// event authoritative in the indexes (or invisible to queries). This mirrors `forceDeleteEvent`
	/// for the removal side and `scribeNewEvent` for the insertion side, all within one transaction.
	private func replaceEventWithRewritten(_ oldEvent: TesseraSignedEvent, with newEvent: TesseraSignedEvent, tx: borrowing Transaction<Write>) throws {
		// ---- Remove the original event from the main store and every index ----
		try signedEvents.deleteEntry(key: oldEvent.unsignedEvent.id, tx: tx)
		try authorIndex.deleteEntry(key: oldEvent.unsignedEvent.publicKey, value: oldEvent.unsignedEvent.id, tx: tx)
		try applicationIndex.deleteEntry(key: oldEvent.unsignedEvent.application, value: oldEvent.unsignedEvent.id, tx: tx)
		try kindIndex.deleteEntry(key: oldEvent.unsignedEvent.kind, value: oldEvent.unsignedEvent.id, tx: tx)
		try dateIndex.deleteEntry(key: oldEvent.unsignedEvent.date, value: oldEvent.unsignedEvent.id, tx: tx)

		for tag in oldEvent.unsignedEvent.tags.array {
			guard let dbTag = tag.unwrap(as: EventTag.self) else { continue }
			try tagIndex.deleteEntry(key: dbTag, value: oldEvent.unsignedEvent.id, tx: tx)
		}

		let oldKindInt = oldEvent.unsignedEvent.kind.RAW_native() % 40_000
		if !NostrKindCategory.nonReplaceable.range.contains(oldKindInt) {
			var dTag: DTag? = nil
			for tag in oldEvent.unsignedEvent.tags.array {
				guard let t = tag.unwrap(as: DTag.self) else { continue }
				dTag = t
				break
			}
			let replaceableKey = ReplaceableKey(pubkey: oldEvent.unsignedEvent.publicKey, kind: oldEvent.unsignedEvent.kind, dTag: dTag)
			let datedId = DatedID(date: oldEvent.unsignedEvent.date, id: oldEvent.unsignedEvent.id)
			try replaceableEvents.deleteEntry(key: replaceableKey, value: datedId, tx: tx)
		}

		// ---- Store the rewritten event and add it to every index ----
		try signedEvents.setEntry(key: newEvent.unsignedEvent.id, value: newEvent, flags: [], tx: tx)
		try authorIndex.setEntry(key: newEvent.unsignedEvent.publicKey, value: newEvent.unsignedEvent.id, flags: [], tx: tx)
		try applicationIndex.setEntry(key: newEvent.unsignedEvent.application, value: newEvent.unsignedEvent.id, flags: [], tx: tx)
		try kindIndex.setEntry(key: newEvent.unsignedEvent.kind, value: newEvent.unsignedEvent.id, flags: [], tx: tx)
		try dateIndex.setEntry(key: newEvent.unsignedEvent.date, value: newEvent.unsignedEvent.id, flags: [], tx: tx)

		for tag in newEvent.unsignedEvent.tags.array {
			guard let dbTag = tag.unwrap(as: EventTag.self) else { continue }
			try tagIndex.setEntry(key: dbTag, value: newEvent.unsignedEvent.id, flags: [], tx: tx)
		}

		let newKindInt = newEvent.unsignedEvent.kind.RAW_native() % 40_000
		if !NostrKindCategory.nonReplaceable.range.contains(newKindInt) {
			let replaceableKey = try ReplaceableKey(event: newEvent.unsignedEvent)
			let datedId = DatedID(date: newEvent.unsignedEvent.date, id: newEvent.unsignedEvent.id)
			try replaceableEvents.setEntry(key: replaceableKey, value: datedId, flags: [], tx: tx)
		}
	}

	/// The admin signs a rewritten copy of the event (preserving the original author), which fully
	/// replaces the stored event in the main store and all indexes.
	/// CLI specific function to force update an event.
	public func forceUpdateEvent(
		id:NOSTR_id,
		admin: MemoryGuarded<RAW_ed25519.PrivateKey>,
		addTags: [any NOSTR_tag]? = nil,
		removeTags: [any NOSTR_tag]? = nil,
		overwriteTags: [any NOSTR_tag]? = nil,
		newContent: ByteBuffer? = nil)
	{
		do {
			let newTrans = try Transaction<Write>(env:env)
			let signedEvent = try signedEvents.loadEntry(key: id, tx: newTrans)
			let updatedEvent = try createNewUpdatedEvent(signedEvent, adminSigningKey: admin, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, content: newContent)
			try replaceEventWithRewritten(signedEvent, with: updatedEvent, tx: newTrans)
			try newTrans.commit()
			log.info(Logger.Message.orange("successfully force updated event"), metadata: ["event_id": "\(id)", "new_event_id": "\(String(describing: updatedEvent.unsignedEvent.id))"])
		} catch let error {
			log.error(Logger.Message.red("failed to force update event"), metadata: ["event_id": "\(id)", "error": "\(error)"])
		}
	}

	/// The admin signs rewritten copies of every event matching the filter (preserving each original
	/// author), each fully replacing the stored event in the main store and all indexes.
	/// CLI specific function to force update events matching the corresponding filter.
	public func forceUpdateEventFiltered(
		filters:[Filter],
		admin: MemoryGuarded<RAW_ed25519.PrivateKey>,
		addTags: [any NOSTR_tag]? = nil,
		removeTags: [any NOSTR_tag]? = nil,
		overwriteTags: [any NOSTR_tag]? = nil,
		newContent: ByteBuffer? = nil)
	{
		do {
			let newTrans = try Transaction<Write>(env:env)
			let (allFilterIds, _) = try getFilterEligibleIds(filters: filters, tx: newTrans)

			for id in allFilterIds {
				let signedEvent = try signedEvents.loadEntry(key: id, tx: newTrans)
				let updatedEvent = try createNewUpdatedEvent(signedEvent, adminSigningKey: admin, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, content: newContent)
				try replaceEventWithRewritten(signedEvent, with: updatedEvent, tx: newTrans)
			}
			try newTrans.commit()
			log.info(Logger.Message.orange("successfully force updated \(allFilterIds.count) events matching the filter"))
		} catch {
			log.error(Logger.Message.red("unable to force update events matching the filter"), metadata: ["error": "\(error)"])
		}
	}
}
