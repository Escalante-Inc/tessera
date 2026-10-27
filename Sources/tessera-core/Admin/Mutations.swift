import Foundation
import RAW
import RAW_base64
import RAW_dh25519
import QuickLMDB
import nostr_kit_swift
import Logging

extension TesseraDB {
	/// Permanently removes a user's kind-0 record: the `userIndex` entry and the
	/// underlying profile event plus all of its index entries. This is an
	/// administrative deletion (like `forceDeleteEvent`) — it does not follow the
	/// Nostr kind-5 protocol, because a kind-5 event only marks an event deleted
	/// and never clears the `userIndex`, so the user would keep appearing in
	/// admin surfaces. The user's *other* events are left untouched.
	public func adminDeleteUser(publicKey:PublicKey, logLevel:Logger.Level) throws {
		var logger = log
		logger.logLevel = logLevel
		try adminDeleteUserTx(publicKey: publicKey)
		logger.info("successfully deleted user", metadata: ["public_key":"\(publicKey)"])
	}

	@MDB_transact(.readWrite)
	private func adminDeleteUserTx(publicKey:PublicKey) throws {
		// resolve the user's profile event from the user index (throws notFound
		// when the user does not exist, which propagates to the caller).
		guard let profileID:NOSTR_id = try #load(TesseraDB.self, database: \.userIndex, key: publicKey) else {
			throw LMDBError.notFound
		}
		try #delete(TesseraDB.self, database: \.userIndex, key: publicKey)

		guard let deletedEvent = try #load(TesseraDB.self, database: \.signedEvents, key: profileID) else {
			throw LMDBError.notFound
		}
		try #delete(TesseraDB.self, database: \.signedEvents, key: profileID)

		// remove the profile event from every secondary index.
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
			try #delete(TesseraDB.self, database: \.replaceableEvents, key: replaceableKey)
		}
	}
}
