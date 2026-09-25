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
	public func scribeNewEvent(signedEvent:TesseraSignedEvent, logLevel:Logger.Level) throws {
		var logger = log
		logger.logLevel = logLevel
		
		let kind = signedEvent.unsignedEvent.kind.RAW_native() % 40_000
		guard NostrKindCategory.ephemeral.range.contains(kind) == false else {
			throw SignedNoteError.cantStoreEphemeralEvent
		}
		
		let newTrans = try Transaction<Write>(env:env)
		do {
			if try checkWriteAccess(user: signedEvent.unsignedEvent.publicKey, kind: signedEvent.unsignedEvent.kind, tx: newTrans) == false {
				throw AccessLevelError.invalidWriteAccess
			}
		} catch LMDBError.notFound {
			throw AccessLevelError.userDoesNotExist
		}

		// Create Event in the Main DB
		try signedEvents.cursor(tx:newTrans) { cursor in
			// Special check for deletion event
			if signedEvent.unsignedEvent.kind.RAW_native() == 5 {
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
			do {
				guard try cursor.containsEntry(key:signedEvent.unsignedEvent.id) == false else {
					logger.warning(Logger.Message.red("Attempted to write an event that already exists"))
					throw LMDBError.keyExists
				}
			} catch LMDBError.notFound {}
			logger.trace("event id validated as new. writing to db.", metadata: ["event_id":"\(String(describing: signedEvent.unsignedEvent.id))"])
			try cursor.setEntry(key:signedEvent.unsignedEvent.id, value:signedEvent, flags:[.noOverwrite], tx:newTrans)
		}
		
		// Add Event to the indexes
		try authorIndex.setEntry(key: signedEvent.unsignedEvent.publicKey, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		try applicationIndex.setEntry(key: signedEvent.unsignedEvent.application, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		try kindIndex.setEntry(key: signedEvent.unsignedEvent.kind, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		try dateIndex.setEntry(key: signedEvent.unsignedEvent.date, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		
		for tag in signedEvent.unsignedEvent.tags.array {
			guard let unwrappedTag = tag.unwrap(as: EventTag.self) else { continue }
			try tagIndex.setEntry(key: unwrappedTag, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		}
		
		if !NostrKindCategory.nonReplaceable.range.contains(kind) {
			let replaceableKey = try ReplaceableKey(event: signedEvent.unsignedEvent)
			let datedId = DatedID(date: signedEvent.unsignedEvent.date, id: signedEvent.unsignedEvent.id)
			
			try replaceableEvents.setEntry(key: replaceableKey, value: datedId, flags: [], tx: newTrans)
		}
		
		try newTrans.commit()
		logger.debug(Logger.Message.green("successfully wrote event to database"))
	}
	
	/// Scribes a new user event to the database.
	public func scribeNewUser(signedEvent:TesseraSignedEvent, logLevel:Logger.Level) throws {
		var logger = log
		logger.logLevel = logLevel
		guard signedEvent.unsignedEvent.kind.RAW_native() == TesseraKinds.user.value else {
			throw SignedNoteError.invalidUserNote
		}
		
		// Add to user index if it's a user
		logger.trace("opening transaction to write data to events database")
		let newTrans = try Transaction<Write>(env:env)
		try userIndex.cursor(tx:newTrans) { cursor in
			guard try cursor.containsEntry(key:signedEvent.unsignedEvent.publicKey) == false else {
				logger.warning(Logger.Message.red("Attempted to write a user that already exists. An administrator can either edit the original user or delete it."))
				throw LMDBError.keyExists
			}
			try cursor.setEntry(key:signedEvent.unsignedEvent.publicKey, value:signedEvent.unsignedEvent.id, flags:[.noOverwrite], tx:newTrans)
		}
		
		try signedEvents.cursor(tx:newTrans) { cursor in
			do {
				guard try cursor.containsEntry(key:signedEvent.unsignedEvent.id) == false else {
					logger.warning(Logger.Message.red("Attempted to write an event that already exists"))
					throw LMDBError.keyExists
				}
			} catch LMDBError.notFound {}
			logger.trace("event id validated as new. writing to db.", metadata: ["event_id":"\(String(describing: signedEvent.unsignedEvent.id))"])
			try cursor.setEntry(key:signedEvent.unsignedEvent.id, value:signedEvent, flags:[.noOverwrite], tx:newTrans)
		}
		
		// Add Event to the indexes
		try authorIndex.setEntry(key: signedEvent.unsignedEvent.publicKey, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		try applicationIndex.setEntry(key: signedEvent.unsignedEvent.application, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		try kindIndex.setEntry(key: signedEvent.unsignedEvent.kind, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		try dateIndex.setEntry(key: signedEvent.unsignedEvent.date, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		
		for tag in signedEvent.unsignedEvent.tags.array {
			guard let unwrappedTag = tag.unwrap(as: EventTag.self) else { continue }
			try tagIndex.setEntry(key: unwrappedTag, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans) 
		}
		
		try newTrans.commit()
		logger.debug(Logger.Message.green("successfully wrote event to database"))
	}
}
