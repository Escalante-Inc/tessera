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
	@MDB_transact(.readWrite)
	private func replaceEventWithRewritten(_ oldEvent: TesseraSignedEvent, with newEvent: TesseraSignedEvent) throws {
		// ---- Remove the original event from the main store and every index ----
		try #delete(TesseraDB.self, database: \.signedEvents, key: oldEvent.unsignedEvent.id)
		try #delete(TesseraDB.self, database: \.authorIndex, key: oldEvent.unsignedEvent.publicKey, value: oldEvent.unsignedEvent.id)
		try #delete(TesseraDB.self, database: \.applicationIndex, key: oldEvent.unsignedEvent.application, value: oldEvent.unsignedEvent.id)
		try #delete(TesseraDB.self, database: \.kindIndex, key: oldEvent.unsignedEvent.kind, value: oldEvent.unsignedEvent.id)
		try #delete(TesseraDB.self, database: \.dateIndex, key: oldEvent.unsignedEvent.date, value: oldEvent.unsignedEvent.id)

		for tag in oldEvent.unsignedEvent.tags.array {
			guard let dbTag = tag.unwrap(as: EventTag.self) else { continue }
			try #delete(TesseraDB.self, database: \.tagIndex, key: dbTag, value: oldEvent.unsignedEvent.id)
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
			try #delete(TesseraDB.self, database: \.replaceableEvents, key: replaceableKey, value: datedId)
		}

		// ---- Store the rewritten event and add it to every index ----
		try #store(TesseraDB.self, database: \.signedEvents, key: newEvent.unsignedEvent.id, value: newEvent)
		try #store(TesseraDB.self, database: \.authorIndex, key: newEvent.unsignedEvent.publicKey, value: newEvent.unsignedEvent.id)
		try #store(TesseraDB.self, database: \.applicationIndex, key: newEvent.unsignedEvent.application, value: newEvent.unsignedEvent.id)
		try #store(TesseraDB.self, database: \.kindIndex, key: newEvent.unsignedEvent.kind, value: newEvent.unsignedEvent.id)
		try #store(TesseraDB.self, database: \.dateIndex, key: newEvent.unsignedEvent.date, value: newEvent.unsignedEvent.id)

		for tag in newEvent.unsignedEvent.tags.array {
			guard let dbTag = tag.unwrap(as: EventTag.self) else { continue }
			try #store(TesseraDB.self, database: \.tagIndex, key: dbTag, value: newEvent.unsignedEvent.id)
		}

		let newKindInt = newEvent.unsignedEvent.kind.RAW_native() % 40_000
		if !NostrKindCategory.nonReplaceable.range.contains(newKindInt) {
			let replaceableKey = try ReplaceableKey(event: newEvent.unsignedEvent)
			let datedId = DatedID(date: newEvent.unsignedEvent.date, id: newEvent.unsignedEvent.id)
			try #store(TesseraDB.self, database: \.replaceableEvents, key: replaceableKey, value: datedId)
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
			let updatedEvent = try forceUpdateEventTx(id: id, admin: admin, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, content: newContent)
			log.info(Logger.Message.orange("successfully force updated event"), metadata: ["event_id": "\(id)", "new_event_id": "\(String(describing: updatedEvent.unsignedEvent.id))"])
		} catch let error {
			log.error(Logger.Message.red("failed to force update event"), metadata: ["event_id": "\(id)", "error": "\(error)"])
		}
	}

	@MDB_transact(.readWrite)
	private func forceUpdateEventTx(
		id:NOSTR_id,
		admin: MemoryGuarded<RAW_ed25519.PrivateKey>,
		addTags: [any NOSTR_tag]?,
		removeTags: [any NOSTR_tag]?,
		overwriteTags: [any NOSTR_tag]?,
		content: ByteBuffer?) throws -> TesseraSignedEvent
	{
		guard let signedEvent = try #load(TesseraDB.self, database: \.signedEvents, key: id) else { throw LMDBError.notFound }
		let updatedEvent = try createNewUpdatedEvent(signedEvent, adminSigningKey: admin, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, content: content)
		try #MDB_transacted(replaceEventWithRewritten(signedEvent, with: updatedEvent))
		return updatedEvent
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
			let count = try forceUpdateEventFilteredTx(filters: filters, admin: admin, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, content: newContent)
			log.info(Logger.Message.orange("successfully force updated \(count) events matching the filter"))
		} catch {
			log.error(Logger.Message.red("unable to force update events matching the filter"), metadata: ["error": "\(error)"])
		}
	}

	@MDB_transact(.readWrite)
	private func forceUpdateEventFilteredTx(
		filters:[Filter],
		admin: MemoryGuarded<RAW_ed25519.PrivateKey>,
		addTags: [any NOSTR_tag]?,
		removeTags: [any NOSTR_tag]?,
		overwriteTags: [any NOSTR_tag]?,
		content: ByteBuffer?) throws -> Int
	{
		let (allFilterIds, _) = try #MDB_transacted(getFilterEligibleIds(filters: filters))

		for id in allFilterIds {
			guard let signedEvent = try #load(TesseraDB.self, database: \.signedEvents, key: id) else { throw LMDBError.notFound }
			let updatedEvent = try createNewUpdatedEvent(signedEvent, adminSigningKey: admin, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, content: content)
			try #MDB_transacted(replaceEventWithRewritten(signedEvent, with: updatedEvent))
		}
		return allFilterIds.count
	}
}
