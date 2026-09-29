import Logging
import Foundation
import NIO
import RAW
import RAW_dh25519
import bedrock
import QuickLMDB
import nostr_kit_swift

extension TesseraDB {
	/// Rebuilds the query indexes from the primary `signedEvents` database.
	///
	/// The negentropy sync path writes events directly into `signedEvents`,
	/// bypassing `scribeNewEvent` (which normally maintains the indexes and runs
	/// access/signature checks). After a sync finishes, call this method so that
	/// queries (which resolve filters through the indexes) can see the synced events.
	///
	/// Every event in `signedEvents` is verified before being indexed:
	/// - its stored key must equal the event's computed id (`unsignedEvent.id`)
	/// - its digital signature must be valid
	/// Entries that fail verification are deleted from the database entirely, so a
	/// corrupt or malicious sync peer cannot poison the local store.
	///
	/// Index updates are idempotent (`noDupData`): events that were already indexed
	/// by a previous pass are skipped rather than duplicated.
	@MDB_transact(.readWrite)
	public func reindexAfterSync(logLevel: Logger.Level) throws {
		var logger = log
		logger.logLevel = logLevel

		// Pass 1: collect bad keys while iterating (deleting during iteration is unsafe).
		var badKeys: [NOSTR_id] = []
		try #cursor(TesseraDB.self, database: \.signedEvents) { cursor in
			if let entry = try? cursor.opFirst(returning: (key: NOSTR_id, value: TesseraSignedEvent).self) {
				var iterator: (key: NOSTR_id, value: TesseraSignedEvent)? = entry
				while iterator != nil {
					let key = iterator!.key
					let value = iterator!.value
					var isVerified = value.isValidSignature() && value.unsignedEvent.id == key
					if isVerified {
						// Events the query engine cannot index must be dropped too: a
						// parameterized-replaceable event (kind 30_000..<40_000) that is
						// missing its required d-tag makes `ReplaceableKey(event:)` throw,
						// which would abort the whole reindex and poison smart-filter
						// queries. Such events are also rejected at scribe time, so the
						// only way one can appear here is via a raw sync — the exact
						// tamper path this pass is meant to sweep.
						let kind = value.unsignedEvent.kind.RAW_native() % 40_000
						if !NostrKindCategory.nonReplaceable.range.contains(kind) && (try? ReplaceableKey(event: value.unsignedEvent)) == nil {
							isVerified = false
						}
					}
					if !isVerified {
						logger.warning("Synced event failed verification; dropping", metadata: ["event_id": "\(String(describing: key))"])
						badKeys.append(key)
					}
					iterator = try? cursor.opNext(returning: (key: NOSTR_id, value: TesseraSignedEvent).self)
				}
			}
		}

		// Pass 2: remove unverified events.
		for key in badKeys {
			try? #delete(TesseraDB.self, database: \.signedEvents, key: key)
		}

		// Pass 3: reindex all remaining events idempotently.
		try #cursor(TesseraDB.self, database: \.signedEvents) { cursor in
			if let entry = try? cursor.opFirst(returning: (key: NOSTR_id, value: TesseraSignedEvent).self) {
				var iterator: (key: NOSTR_id, value: TesseraSignedEvent)? = entry
				while iterator != nil {
					let signedEvent = iterator!.value
					// Mirrors the indexing portion of `scribeNewEvent`.
					let unsignedEvent = signedEvent.unsignedEvent
					try? #store(TesseraDB.self, database: \.authorIndex, key: unsignedEvent.publicKey, value: unsignedEvent.id, flags: [.noDupData])
					try? #store(TesseraDB.self, database: \.applicationIndex, key: unsignedEvent.application, value: unsignedEvent.id, flags: [.noDupData])
					try? #store(TesseraDB.self, database: \.kindIndex, key: unsignedEvent.kind, value: unsignedEvent.id, flags: [.noDupData])
					try? #store(TesseraDB.self, database: \.dateIndex, key: unsignedEvent.date, value: unsignedEvent.id, flags: [.noDupData])

					for tag in unsignedEvent.tags.array {
						guard let unwrappedTag = tag.unwrap(as: EventTag.self) else { continue }
						try? #store(TesseraDB.self, database: \.tagIndex, key: unwrappedTag, value: unsignedEvent.id, flags: [.noDupData])
					}

					let kindInt = unsignedEvent.kind.RAW_native() % 40_000
					if !NostrKindCategory.nonReplaceable.range.contains(kindInt) {
						let replaceableKey = try ReplaceableKey(event: unsignedEvent)
						let datedId = DatedID(date: unsignedEvent.date, id: unsignedEvent.id)
						try? #store(TesseraDB.self, database: \.replaceableEvents, key: replaceableKey, value: datedId, flags: [.noDupData])
					}
					iterator = try? cursor.opNext(returning: (key: NOSTR_id, value: TesseraSignedEvent).self)
				}
			}
		}

		logger.debug("Successfully reindexed database after sync")
	}
}
