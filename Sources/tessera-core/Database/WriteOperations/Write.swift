import Logging
import Foundation
import NIO
import RAW
import RAW_ed25519
import bedrock
import QuickLMDB
import nostr_kit_swift

extension TesseraDB {
	/// Scribes a new (Signature Confirmed) events into the events database.
	// Scribing new events may change based on the kind of event.
	// Kind 5 can only be scribed if the referenced deleted event exists.
	@MDB_transact(.readWrite)
	public func scribeNewEvent(signedEvent:TesseraSignedEvent, logLevel:Logger.Level) throws {
		var logger = log
		logger.logLevel = logLevel
		
		let kind = signedEvent.unsignedEvent.kind.RAW_native() % 40_000
		guard NostrKindCategory.ephemeral.range.contains(kind) == false else {
			throw SignedNoteError.cantStoreEphemeralEvent
		}
		
		do {
			if try #MDB_transacted(checkWriteAccess(user: signedEvent.unsignedEvent.publicKey, kind: signedEvent.unsignedEvent.kind)) == false {
				throw AccessLevelError.invalidWriteAccess
			}
		} catch LMDBError.notFound {
			throw AccessLevelError.userDoesNotExist
		}

		// Create Event in the Main DB
		// Special check for deletion event
		if signedEvent.unsignedEvent.kind.RAW_native() == 5 {
			try #cursor(TesseraDB.self, database: \.signedEvents) { cursor in
				for tag in signedEvent.unsignedEvent.tags.array {
					do {
						guard let eventRefTag = tag.unwrap(as: EventRefTag.self) else { continue }
						let id = eventRefTag.value
						let event = try cursor.opSet(key: id)
						guard event.unsignedEvent.publicKey == signedEvent.unsignedEvent.publicKey else {
							throw SignedNoteError.invalidKind5PublicKey
						}
					} catch SignedNoteError.invalidKind5PublicKey {
						throw SignedNoteError.invalidKind5PublicKey
					} catch {
						throw SignedNoteError.invalidKind5Tag
					}
				}
			}
		}
		do {
			guard try #contains(TesseraDB.self, database: \.signedEvents, key: signedEvent.unsignedEvent.id) == false else {
				logger.warning(Logger.Message.red("Attempted to write an event that already exists"))
				throw LMDBError.keyExists
			}
		} catch LMDBError.notFound {}
		logger.trace("event id validated as new. writing to db.", metadata: ["event_id":"\(String(describing: signedEvent.unsignedEvent.id))"])
		try #store(TesseraDB.self, database: \.signedEvents, key: signedEvent.unsignedEvent.id, value: signedEvent, flags: [.noOverwrite])
		
		// Add Event to the indexes
		try #store(TesseraDB.self, database: \.authorIndex, key: signedEvent.unsignedEvent.publicKey, value: signedEvent.unsignedEvent.id)
		try #store(TesseraDB.self, database: \.applicationIndex, key: signedEvent.unsignedEvent.application, value: signedEvent.unsignedEvent.id)
		try #store(TesseraDB.self, database: \.kindIndex, key: signedEvent.unsignedEvent.kind, value: signedEvent.unsignedEvent.id)
		try #store(TesseraDB.self, database: \.dateIndex, key: signedEvent.unsignedEvent.date, value: signedEvent.unsignedEvent.id)
		
		for tag in signedEvent.unsignedEvent.tags.array {
			guard let unwrappedTag = tag.unwrap(as: EventTag.self) else { continue }
			try #store(TesseraDB.self, database: \.tagIndex, key: unwrappedTag, value: signedEvent.unsignedEvent.id)
		}
		
		if !NostrKindCategory.nonReplaceable.range.contains(kind) {
			let replaceableKey = try ReplaceableKey(event: signedEvent.unsignedEvent)
			let datedId = DatedID(date: signedEvent.unsignedEvent.date, id: signedEvent.unsignedEvent.id)
			
			try #store(TesseraDB.self, database: \.replaceableEvents, key: replaceableKey, value: datedId)
		}
		
		logger.debug(Logger.Message.green("successfully wrote event to database"))
	}
	
	/// Scribes a new user event to the database.
	@MDB_transact(.readWrite)
	public func scribeNewUser(signedEvent:TesseraSignedEvent, logLevel:Logger.Level) throws {
		var logger = log
		logger.logLevel = logLevel
		guard signedEvent.unsignedEvent.kind.RAW_native() == TesseraKinds.user.value else {
			throw SignedNoteError.invalidUserNote
		}
		
		// Add to user index if it's a user
		logger.trace("opening transaction to write data to events database")
		do {
			guard try #contains(TesseraDB.self, database: \.userIndex, key: signedEvent.unsignedEvent.publicKey) == false else {
				logger.warning(Logger.Message.red("Attempted to write a user that already exists. An administrator can either edit the original user or delete it."))
				throw LMDBError.keyExists
			}
		} catch LMDBError.notFound {}
		try #store(TesseraDB.self, database: \.userIndex, key: signedEvent.unsignedEvent.publicKey, value: signedEvent.unsignedEvent.id, flags: [.noOverwrite])
		
		do {
			guard try #contains(TesseraDB.self, database: \.signedEvents, key: signedEvent.unsignedEvent.id) == false else {
				logger.warning(Logger.Message.red("Attempted to write an event that already exists"))
				throw LMDBError.keyExists
			}
		} catch LMDBError.notFound {}
		logger.trace("event id validated as new. writing to db.", metadata: ["event_id":"\(String(describing: signedEvent.unsignedEvent.id))"])
		try #store(TesseraDB.self, database: \.signedEvents, key: signedEvent.unsignedEvent.id, value: signedEvent, flags: [.noOverwrite])
		
		// Add Event to the indexes
		try #store(TesseraDB.self, database: \.authorIndex, key: signedEvent.unsignedEvent.publicKey, value: signedEvent.unsignedEvent.id)
		try #store(TesseraDB.self, database: \.applicationIndex, key: signedEvent.unsignedEvent.application, value: signedEvent.unsignedEvent.id)
		try #store(TesseraDB.self, database: \.kindIndex, key: signedEvent.unsignedEvent.kind, value: signedEvent.unsignedEvent.id)
		try #store(TesseraDB.self, database: \.dateIndex, key: signedEvent.unsignedEvent.date, value: signedEvent.unsignedEvent.id)
		
		for tag in signedEvent.unsignedEvent.tags.array {
			guard let unwrappedTag = tag.unwrap(as: EventTag.self) else { continue }
			try #store(TesseraDB.self, database: \.tagIndex, key: unwrappedTag, value: signedEvent.unsignedEvent.id)
		}
		
		logger.debug(Logger.Message.green("successfully wrote event to database"))
	}
}
