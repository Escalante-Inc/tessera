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
	/// Force updates a users username.
	public func forceUpdateUser(publicEd25519Key: PublicKey, username: String) {
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			var user = try users.loadEntry(key: publicEd25519Key, tx: newTrans)
			user.userName = EncodedString(stringLiteral: username)
			try users.setEntry(key: publicEd25519Key, value: user, flags: [], tx: newTrans)
			try newTrans.commit()
		} catch let error {
			log.error(Logger.Message.red("failed to force update user"), metadata: ["public_key": "\(publicEd25519Key)", "error": "\(error)"])
		}
		log.info(Logger.Message.orange("successfully force updated user"), metadata: ["public_key": "\(publicEd25519Key)"])
	}
}

extension TesseraDB {
	/// WARNING: This function does not follow Nostr update protocol. Use with caution.
	/// WARNING: Updating notes in a manner that's not valid with Nostr will go through. Use with caution.
	/// WARNING: The admin becomes the author of any notes updated forcefully.
	/// CLI specific function to force update an event.
	public func forceUpdateEvent(
		id:NOSTR_id,
		admin: MemoryGuarded<PrivateKey>,
		newDate: NOSTR_date? = nil,
		addTags: [any NOSTR_tag]? = nil,
		removeTags: [any NOSTR_tag]? = nil,
		overwriteTags: [any NOSTR_tag]? = nil,
		newKind: NOSTR_kind? = nil,
		newContent: ByteBuffer? = nil)
	{
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			let sse = try signedEvents.loadEntry(key: id, tx: newTrans)
			let user = try users.loadEntry(key: sse.event.unsignedEvent.publicKey, tx: newTrans)
			let (_, edPrivKey) = try Ed25519.generateKeys(secretKey: user.privateKey)
			let updatedEvent = try createNewUpdatedEvent(sse.event, authorSigningKey: edPrivKey, admin: admin, newDate: newDate, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, kind: newKind, content: newContent)
			try signedEvents.deleteEntry(key: sse.event.unsignedEvent.id, tx: newTrans)
			try signedEvents.setEntry(key: updatedEvent.unsignedEvent.id, value: StoredSignedEvent(event: updatedEvent, metadata: sse.metadata), flags: [], tx: newTrans)
			try newTrans.commit()
		} catch let error {
			log.error(Logger.Message.red("failed to force update event"), metadata: ["event_id": "\(id)", "error": "\(error)"])
		}
		log.info(Logger.Message.orange("successfully force updated event"), metadata: ["event_id": "\(id)"])
	}
	
	/// WARNING: This function does not follow Nostr update protocol. Use with caution.
	/// WARNING: Updating notes in a manner that's not valid with Nostr will go through. Use with caution.
	/// WARNING: The admin becomes the author of any notes updated forcefully.
	/// CLI specific function to force update events matching the corresponding filter.
	public func forceUpdateEventFiltered(
		filters:[Filter],
		admin: MemoryGuarded<PrivateKey>,
		newDate: NOSTR_date? = nil,
		addTags: [any NOSTR_tag]? = nil,
		removeTags: [any NOSTR_tag]? = nil,
		overwriteTags: [any NOSTR_tag]? = nil,
		newKind: NOSTR_kind? = nil,
		newContent: ByteBuffer? = nil)
	{
		var updatedEvents: [StoredSignedEvent] = []
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			try signedEvents.cursor(tx:newTrans) { cursor in
				let (_, sse) = try cursor.opFirst()
				if eventMatchesFilters(sse.event, filters: filters, logLevel: log.logLevel) {
					let user = try users.loadEntry(key: sse.event.unsignedEvent.publicKey, tx: newTrans)
					let (_, edPrivKey) = try Ed25519.generateKeys(secretKey: user.privateKey)
					try cursor.deleteCurrentEntry(flags: [])
					updatedEvents.append(StoredSignedEvent(event: try createNewUpdatedEvent(sse.event, authorSigningKey: edPrivKey, admin: admin, newDate: newDate, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, kind: newKind, content: newContent), metadata: sse.metadata))
				}
				while let (_, sse) = try? cursor.opNext() {
					if eventMatchesFilters(sse.event, filters: filters, logLevel: log.logLevel) {
						let user = try users.loadEntry(key: sse.event.unsignedEvent.publicKey, tx: newTrans)
						let (_, edPrivKey) = try Ed25519.generateKeys(secretKey: user.privateKey)
						try cursor.deleteCurrentEntry(flags: [])
						updatedEvents.append(StoredSignedEvent(event: try createNewUpdatedEvent(sse.event, authorSigningKey: edPrivKey, admin: admin, newDate: newDate, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, kind: newKind, content: newContent), metadata: sse.metadata))
					}
				}
			}
			for sse in updatedEvents {
				try signedEvents.setEntry(key: sse.event.unsignedEvent.id, value: sse, flags: [], tx: newTrans)
			}
			try newTrans.commit()
		} catch let error {
			log.error(Logger.Message.red("unable to force update events matching the filter"), metadata: ["error": "\(error)"])
		}
		log.info(Logger.Message.orange("successfully force updated \(updatedEvents.count) events matching the filter"))
	}
}
