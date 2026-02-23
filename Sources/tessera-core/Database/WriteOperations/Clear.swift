import Logging
import Foundation
import NIO
import RAW
import bedrock
import QuickLMDB
import nostr_kit_swift

extension TesseraDB {
	/// Deletes all signed events.
	public func clearEventsDatabase() throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		try signedEvents.deleteAllEntries(tx: newTrans)
		try newTrans.commit()
		log.info(Logger.Message.orange("successfully deleted tessera events database"))
	}
	
	/// Deletes all users.
	public func clearUsersDatabase() throws {
		let newTrans = try Transaction(env: env, readOnly: false)
		try users.deleteAllEntries(tx: newTrans)
		try newTrans.commit()
		log.info(Logger.Message.orange("successfully deleted users database"))
	}
}
