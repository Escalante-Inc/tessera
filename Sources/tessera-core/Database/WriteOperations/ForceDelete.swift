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
	/// WARNING: This function does not follow Nostr deletion protocol. Use with caution.
	/// WARNING: This deletes a signed event PERMANENTLY from the database.
	/// CLI specific function to force delete a single event.
	public func forceDeleteEvent(id:NOSTR_id) {
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			let deletedEvent = try signedEvents.loadEntry(key: id, tx: newTrans)
			try signedEvents.deleteEntry(key:id, tx:newTrans)
			
			// Remove Event from the indexes
			try authorIndex.cursor(tx:newTrans) { cursor in
				if try cursor.containsEntry(key: deletedEvent.unsignedEvent.publicKey) {
					var nostrIds = try cursor.opSet(key: deletedEvent.unsignedEvent.publicKey)
					nostrIds.ids.remove(deletedEvent.unsignedEvent.id)
					if nostrIds.ids.isEmpty {
						try cursor.deleteCurrentEntry(flags: [])
					} else {
						try cursor.setEntry(key: deletedEvent.unsignedEvent.publicKey, value: nostrIds, flags: [])
					}
				}
			}
			
			try kindIndex.cursor(tx:newTrans) { cursor in
				if try cursor.containsEntry(key: deletedEvent.unsignedEvent.kind) {
					var nostrIds = try cursor.opSet(key: deletedEvent.unsignedEvent.kind)
					nostrIds.ids.remove(deletedEvent.unsignedEvent.id)
					if nostrIds.ids.isEmpty {
						try cursor.deleteCurrentEntry(flags: [])
					} else {
						try cursor.setEntry(key: deletedEvent.unsignedEvent.kind, value: nostrIds, flags: [])
					}
				}
			}
			
			try dateIndex.cursor(tx:newTrans) { cursor in
				if try cursor.containsEntry(key: deletedEvent.unsignedEvent.date) {
					var nostrIds = try cursor.opSet(key: deletedEvent.unsignedEvent.date)
					nostrIds.ids.remove(deletedEvent.unsignedEvent.id)
					if nostrIds.ids.isEmpty {
						try cursor.deleteCurrentEntry(flags: [])
					} else {
						try cursor.setEntry(key: deletedEvent.unsignedEvent.date, value: nostrIds, flags: [])
					}
				}
			}
			
			try tagIndex.cursor(tx:newTrans) { cursor in
				for tag in deletedEvent.unsignedEvent.tags.array {
					var dbTag = tag
					// Tags are indexed on their name and only the first item in the values array
					if tag.NOSTR_tag_values.array.count > 1 {
						dbTag.NOSTR_tag_values.array = [dbTag.NOSTR_tag_values.array.first!]
					}
					var nostrIds = try cursor.opSet(key: dbTag as! EventTag)
					nostrIds.ids.remove(deletedEvent.unsignedEvent.id)
					if nostrIds.ids.isEmpty {
						try cursor.deleteCurrentEntry(flags: [])
					} else {
						try cursor.setEntry(key: dbTag as! EventTag, value: nostrIds, flags: [])
					}
				}
			}
			
			if isReplaceableKind(deletedEvent.unsignedEvent.kind) {
				var dTag:(any NOSTR_tag_value)? = nil
				if let tag = deletedEvent.unsignedEvent.tags.array.first(where: { $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "d") }) {
					dTag = tag.NOSTR_tag_values.array.first!
				}
				let replaceableKey = ReplaceableKey(pubkey: deletedEvent.unsignedEvent.publicKey, kind: deletedEvent.unsignedEvent.kind, dTag: dTag)
				try replaceableEvents.cursor(tx: newTrans) { cursor in
					var nostrIds = try cursor.opSet(key: replaceableKey)
					if let index = nostrIds.ids.firstIndex(of: deletedEvent.unsignedEvent.id) {
						nostrIds.ids.remove(at: index)
					}
					if nostrIds.ids.isEmpty {
						try cursor.deleteCurrentEntry(flags: [])
					} else {
						try cursor.setEntry(key: replaceableKey, value: nostrIds, flags: [])
					}
				}
			}
			
			
			log.info(Logger.Message.orange("successfully force deleted event"), metadata: ["event_id":"\(id)"])
			try newTrans.commit()
		} catch let error {
			log.error(Logger.Message.red("Failed to delete event due to internal error."), metadata: ["error":"\(error)"])
		}
	}
	
	/// WARNING: This function does not follow Nostr deletion protocol. Use with caution.
	/// WARNING: This deletes signed events PERMANENTLY from the database.
	/// CLI specific function to force delete events matching the corresponding filter.
	public func forceDeleteEventFiltered(filters:[Filter]) {
		var deletedEvents: [TesseraSignedEvent] = []
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			try signedEvents.cursor(tx:newTrans) { cursor in
				let (_, val) = try cursor.opFirst()
				if eventMatchesFilters(val, filters: filters, logLevel: log.logLevel) {
					try cursor.deleteCurrentEntry(flags: []); deletedEvents.append(val)
				}
				while let (_, val) = try? cursor.opNext() {
					if eventMatchesFilters(val, filters: filters, logLevel: log.logLevel) {
						try cursor.deleteCurrentEntry(flags: []); deletedEvents.append(val)
					}
				}
			}
			try newTrans.commit()
		} catch {
			log.error(Logger.Message.red("Failed to delete events due to internal error."), metadata: ["error":"\(error)"])
		}
		log.info(Logger.Message.orange("successfully force deleted \(deletedEvents.count) events"))
	}
}
