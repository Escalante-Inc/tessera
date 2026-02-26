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
		
		guard (20_000...29_999).contains(signedEvent.unsignedEvent.kind.RAW_native()) == false else {
			throw SignedNoteError.cantStoreEphemeralEvent
		}

		// Create Event in the Main DB
		logger.trace("opening transaction to write data to events database")
		let newTrans = try Transaction(env:env, readOnly:false)
		try signedEvents.cursor(tx:newTrans) { cursor in
			if signedEvent.unsignedEvent.kind.RAW_native() == 5 {
				for tag in signedEvent.unsignedEvent.tags.array {
					do {
						let event = try cursor.opSet(key: tag.NOSTR_tag_values.array.first! as! NOSTR_id)
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
			try cursor.setEntry(key:signedEvent.unsignedEvent.id, value:signedEvent, flags:[.noOverwrite])
		}
		
		// Add Event to the indexes
		try authorIndex.setEntry(key: signedEvent.unsignedEvent.publicKey, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		try kindIndex.setEntry(key: signedEvent.unsignedEvent.kind, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		try dateIndex.setEntry(key: signedEvent.unsignedEvent.date, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		
		for tag in signedEvent.unsignedEvent.tags.array {
			var dbTag = tag
			// Tags are indexed on their name and only the first item in the values array
			if tag.NOSTR_tag_values.array.count > 1 {
				dbTag.NOSTR_tag_values.array = [dbTag.NOSTR_tag_values.array.first!]
			}
			try tagIndex.setEntry(key: dbTag as! EventTag, value: signedEvent.unsignedEvent.id, flags: [], tx: newTrans)
		}
		
		if isReplaceableKind(signedEvent.unsignedEvent.kind) {
			var dTag:(any NOSTR_tag_value)? = nil
			if let tag = signedEvent.unsignedEvent.tags.array.first(where: { $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "d") }) {
				dTag = tag.NOSTR_tag_values.array.first!
			}
			let replaceableKey = ReplaceableKey(pubkey: signedEvent.unsignedEvent.publicKey, kind: signedEvent.unsignedEvent.kind, dTag: dTag)
			let datedId = DatedID(date: signedEvent.unsignedEvent.date, id: signedEvent.unsignedEvent.id)
			
			try replaceableEvents.setEntry(key: replaceableKey, value: datedId, flags: [], tx: newTrans)
		}
		
		try newTrans.commit()
		logger.debug(Logger.Message.green("successfully wrote event to database"))
	}
}
