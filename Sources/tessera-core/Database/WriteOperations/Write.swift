import Logging
import Foundation
import NIO
import RAW
import RAW_ed25519
import bedrock
import QuickLMDB
import nostr_kit_swift

extension TesseraDB {
	
	/// Scribes a new user into the users database.
	public func scribeNewUser(user:User, logLevel:Logger.Level) throws {
		var logger = log
		logger.logLevel = logLevel

		let (edPubKey, _) = try Ed25519.generateKeys(secretKey: user.privateKey)
		logger.trace("opening transaction to write data to users database")
		let newTrans = try Transaction(env:env, readOnly:false)
		try users.cursor(tx:newTrans) { cursor in
			do {
				guard try cursor.containsEntry(key:edPubKey) == false else {
					logger.warning(Logger.Message.red("Attempted to write a user that already exists"))
					throw LMDBError.keyExists
				}
			} catch LMDBError.notFound {}
			logger.trace("user validated as new. writing to db.", metadata: ["username":"\(String(user.userName))"])
			try cursor.setEntry(key:edPubKey, value:user, flags:[.noOverwrite])
		}
		try newTrans.commit()
		logger.debug(Logger.Message.green("successfully wrote user to database"))
	}
	
	/// Scribes a new (Signature Confirmed) events into the events database.
	// Scribing new events may change based on the kind of event.
	// Kind 5 can only be scribed if the referenced deleted event exists.
	public func scribeNewEvent(signedEvent:StoredSignedEvent, logLevel:Logger.Level) throws {
		var logger = log
		logger.logLevel = logLevel

		logger.trace("opening transaction to write data to events database")
		let newTrans = try Transaction(env:env, readOnly:false)
		try signedEvents.cursor(tx:newTrans) { cursor in
			do {
				guard try cursor.containsEntry(key:signedEvent.event.unsignedEvent.id) == false else {
					logger.warning(Logger.Message.red("Attempted to write an event that already exists"))
					throw LMDBError.keyExists
				}
			} catch LMDBError.notFound {}
			logger.trace("event id validated as new. writing to db.", metadata: ["event_id":"\(String(describing: signedEvent.event.unsignedEvent.id))"])
			try cursor.setEntry(key:signedEvent.event.unsignedEvent.id, value:signedEvent, flags:[.noOverwrite])
		}
		try newTrans.commit()
		logger.debug(Logger.Message.green("successfully wrote event to database"))
	}
}
