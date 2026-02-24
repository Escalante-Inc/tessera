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
	/// While the admin signs the new note, an author tag is added to preserve the original author of the note.
	/// CLI specific function to force update an event.
	public func forceUpdateEvent(
		id:NOSTR_id,
		admin: MemoryGuarded<Ed25519.PrivateKey>,
		addTags: [any NOSTR_tag]? = nil,
		removeTags: [any NOSTR_tag]? = nil,
		overwriteTags: [any NOSTR_tag]? = nil,
		newContent: ByteBuffer? = nil)
	{
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			let sse = try signedEvents.loadEntry(key: id, tx: newTrans)
			let updatedEvent = try createNewUpdatedEvent(sse.event, adminSigningKey: admin, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, content: newContent)
			try signedEvents.setEntry(key: updatedEvent.unsignedEvent.id, value: StoredSignedEvent(event: updatedEvent, metadata: sse.metadata), flags: [], tx: newTrans)
			try newTrans.commit()
		} catch let error {
			log.error(Logger.Message.red("failed to force update event"), metadata: ["event_id": "\(id)", "error": "\(error)"])
		}
		log.info(Logger.Message.orange("successfully force updated event"), metadata: ["event_id": "\(id)"])
	}
	
	/// While the admin signs the new note, an author tag is added to preserve the original author of the note.
	/// CLI specific function to force update events matching the corresponding filter.
	public func forceUpdateEventFiltered(
		filters:[Filter],
		admin: MemoryGuarded<Ed25519.PrivateKey>,
		addTags: [any NOSTR_tag]? = nil,
		removeTags: [any NOSTR_tag]? = nil,
		overwriteTags: [any NOSTR_tag]? = nil,
		newContent: ByteBuffer? = nil)
	{
		var updatedEvents: [StoredSignedEvent] = []
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			try signedEvents.cursor(tx:newTrans) { cursor in
				let (_, sse) = try cursor.opFirst()
				if eventMatchesFilters(sse.event, filters: filters, logLevel: log.logLevel) {
					updatedEvents.append(StoredSignedEvent(event: try createNewUpdatedEvent(sse.event, adminSigningKey: admin, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, content: newContent), metadata: sse.metadata))
				}
				while let (_, sse) = try? cursor.opNext() {
					if eventMatchesFilters(sse.event, filters: filters, logLevel: log.logLevel) {
						updatedEvents.append(StoredSignedEvent(event: try createNewUpdatedEvent(sse.event, adminSigningKey: admin, addTags: addTags, removeTags: removeTags, overwriteTags: overwriteTags, content: newContent), metadata: sse.metadata))
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
