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
	/// Force deletes a user givent the user's `Ed25519 PublicKey`
	public func forceDeleteUser(publicKey:PublicKey) {
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			let user = try users.loadEntry(key:publicKey, tx:newTrans)
			try users.deleteEntry(key:publicKey, tx:newTrans)
			log.info(Logger.Message.orange("successfully force deleted user"), metadata:["username":"\(user.userName)", "public_key":"\(publicKey)"])
			try newTrans.commit()
		} catch let error {
			log.error(Logger.Message.red("Failed to delete event due to internal error."), metadata: ["error":"\(error)"])
		}
	}
	
	/// Force deletes a user given the user's username.
	public func forceDeleteUser(username:String) {
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			try users.cursor(tx:newTrans) { cursor in
				let (publicKey, val) = try cursor.opFirst()
				if String(val.userName) == username {
					try cursor.deleteCurrentEntry(flags: [])
					log.info(Logger.Message.orange("successfully force deleted user"), metadata:["username":"\(val.userName)", "public_key":"\(publicKey)"])
				}
				while let (publicKey, val) = try? cursor.opNext() {
					if String(val.userName) == username {
						try cursor.deleteCurrentEntry(flags: [])
						log.info(Logger.Message.orange("successfully force deleted user"), metadata:["username":"\(val.userName)", "public_key":"\(publicKey)"])
					}
				}
			}
			try newTrans.commit()
		} catch let error {
			log.error(Logger.Message.red("Failed to delete user due to internal error."), metadata: ["error":"\(error)"])
		}
		log.warning(Logger.Message.red("Failed to delete user. Username not found!"), metadata: ["username":"\(username)"])
	}
	
	/// WARNING: This function does not follow Nostr deletion protocol. Use with caution.
	/// CLI specific function to force delete a single event.
	public func forceDeleteEvent(id:NOSTR_id) {
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			try signedEvents.deleteEntry(key:id, tx:newTrans)
			log.info(Logger.Message.orange("successfully force deleted event"), metadata: ["event_id":"\(id)"])
			try newTrans.commit()
		} catch let error {
			log.error(Logger.Message.red("Failed to delete event due to internal error."), metadata: ["error":"\(error)"])
		}
	}
	
	/// WARNING: This function does not follow Nostr deletion protocol. Use with caution.
	/// CLI specific function to force delete events matching the corresponding filter.
	public func forceDeleteEventFiltered(filters:[Filter]) {
		var deletedEvents: [StoredSignedEvent] = []
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			try signedEvents.cursor(tx:newTrans) { cursor in
				let (_, val) = try cursor.opFirst()
				if eventMatchesFilters(val.event, filters: filters, logLevel: log.logLevel) {
					try cursor.deleteCurrentEntry(flags: []); deletedEvents.append(val)
				}
				while let (_, val) = try? cursor.opNext() {
					if eventMatchesFilters(val.event, filters: filters, logLevel: log.logLevel) {
						try cursor.deleteCurrentEntry(flags: []); deletedEvents.append(val)
					}
				}
			}
			try newTrans.commit()
		} catch {
			log.error(Logger.Message.red("Failed to delete events due to internal error."), metadata: ["error":"\(error)"])
		}
		log.info(Logger.Message.orange("successfully force deleted \(deletedEvents.count) events"))
		// Maybe add logging about the deleted events too??
	}
}
