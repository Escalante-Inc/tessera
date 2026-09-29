import Logging
import Foundation
import NIO
import RAW
import RAW_base64
import RAW_dh25519
import bedrock
import QuickLMDB
import nostr_kit_swift

extension TesseraDB {
	/// WARNING: This function does not follow Nostr deletion protocol. Use with caution.
	/// WARNING: This deletes a signed event PERMANENTLY from the database.
	/// CLI specific function to force delete a single event.
	public func forceDeleteEvent(id:NOSTR_id) {
		do {
			try forceDeleteEventTx(id: id)
			log.info(Logger.Message.orange("successfully force deleted event"), metadata: ["event_id":"\(id)"])
		} catch let error {
			log.error(Logger.Message.red("Failed to delete event due to internal error."), metadata: ["error":"\(error)"])
		}
	}

	@MDB_transact(.readWrite)
	private func forceDeleteEventTx(id:NOSTR_id) throws {
		guard let deletedEvent = try #load(TesseraDB.self, database: \.signedEvents, key: id) else { throw LMDBError.notFound }
		try #delete(TesseraDB.self, database: \.signedEvents, key: id)

		// Remove Event from the indexes
		try #delete(TesseraDB.self, database: \.authorIndex, key: deletedEvent.unsignedEvent.publicKey, value: deletedEvent.unsignedEvent.id)
		try #delete(TesseraDB.self, database: \.applicationIndex, key: deletedEvent.unsignedEvent.application, value: deletedEvent.unsignedEvent.id)

		try #delete(TesseraDB.self, database: \.kindIndex, key: deletedEvent.unsignedEvent.kind, value: deletedEvent.unsignedEvent.id)

		try #delete(TesseraDB.self, database: \.dateIndex, key: deletedEvent.unsignedEvent.date, value: deletedEvent.unsignedEvent.id)

		for tag in deletedEvent.unsignedEvent.tags.array {
			guard let dbTag = tag.unwrap(as: EventTag.self) else { continue }
			try #delete(TesseraDB.self, database: \.tagIndex, key: dbTag, value: deletedEvent.unsignedEvent.id)
		}

		let kindInt = deletedEvent.unsignedEvent.kind.RAW_native() % 40_000
		if !NostrKindCategory.nonReplaceable.range.contains(kindInt) {
			var dTag:DTag? = nil
			for tag in deletedEvent.unsignedEvent.tags.array {
				guard let t = tag.unwrap(as: DTag.self) else { continue }
				dTag = t
				break
			}

			let replaceableKey = ReplaceableKey(pubkey: deletedEvent.unsignedEvent.publicKey, kind: deletedEvent.unsignedEvent.kind, dTag: dTag)
			let datedId = DatedID(date: deletedEvent.unsignedEvent.date, id: deletedEvent.unsignedEvent.id)

			try #delete(TesseraDB.self, database: \.replaceableEvents, key: replaceableKey, value: datedId)
		}
	}
	
	/// WARNING: This function does not follow Nostr deletion protocol. Use with caution.
	/// WARNING: This deletes signed events PERMANENTLY from the database.
	/// CLI specific function to force delete events matching the corresponding filter.
	public func forceDeleteEventFiltered(filters:[Filter]) {
		do {
			let count = try forceDeleteEventFilteredTx(filters: filters)
			log.info(Logger.Message.orange("successfully force deleted \(count) events"))
		} catch {
			log.error(Logger.Message.red("Failed to delete events due to internal error."), metadata: ["error":"\(error)"])
		}
	}

	@MDB_transact(.readWrite)
	private func forceDeleteEventFilteredTx(filters:[Filter]) throws -> Int {
		let (allFilterIds, _) = try #MDB_transacted(getFilterEligibleIds(filters: filters))

		for id in allFilterIds {
			guard let deletedEvent = try #load(TesseraDB.self, database: \.signedEvents, key: id) else { throw LMDBError.notFound }
			try #delete(TesseraDB.self, database: \.signedEvents, key: id)

			// Remove Event from the indexes
			try #delete(TesseraDB.self, database: \.authorIndex, key: deletedEvent.unsignedEvent.publicKey, value: deletedEvent.unsignedEvent.id)

			try #delete(TesseraDB.self, database: \.kindIndex, key: deletedEvent.unsignedEvent.kind, value: deletedEvent.unsignedEvent.id)

			try #delete(TesseraDB.self, database: \.dateIndex, key: deletedEvent.unsignedEvent.date, value: deletedEvent.unsignedEvent.id)

			for tag in deletedEvent.unsignedEvent.tags.array {
				guard let dbTag = tag.unwrap(as: EventTag.self) else { continue }
				try #delete(TesseraDB.self, database: \.tagIndex, key: dbTag, value: deletedEvent.unsignedEvent.id)
			}

			let kindInt = deletedEvent.unsignedEvent.kind.RAW_native() % 40_000
			if !NostrKindCategory.nonReplaceable.range.contains(kindInt) {
				var dTag:DTag? = nil
				for tag in deletedEvent.unsignedEvent.tags.array {
					guard let t = tag.unwrap(as: DTag.self) else { continue }
					dTag = t
					break
				}

				let replaceableKey = ReplaceableKey(pubkey: deletedEvent.unsignedEvent.publicKey, kind: deletedEvent.unsignedEvent.kind, dTag: dTag)
				let datedId = DatedID(date: deletedEvent.unsignedEvent.date, id: deletedEvent.unsignedEvent.id)

				try #delete(TesseraDB.self, database: \.replaceableEvents, key: replaceableKey, value: datedId)
			}
		}
		return allFilterIds.count
	}
}
