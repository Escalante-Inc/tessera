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
			try authorIndex.deleteEntry(key: deletedEvent.unsignedEvent.publicKey, value: deletedEvent.unsignedEvent.id, tx: newTrans)
			
			try kindIndex.deleteEntry(key: deletedEvent.unsignedEvent.kind, value: deletedEvent.unsignedEvent.id, tx: newTrans)
			
			try dateIndex.deleteEntry(key: deletedEvent.unsignedEvent.date, value: deletedEvent.unsignedEvent.id, tx: newTrans)
			
			
			for tag in deletedEvent.unsignedEvent.tags.array {
				var dbTag = tag
				// Tags are indexed on their name and only the first item in the values array
				if tag.NOSTR_tag_values.array.count > 1 {
					dbTag.NOSTR_tag_values.array = [dbTag.NOSTR_tag_values.array.first!]
				}
				try tagIndex.deleteEntry(key: dbTag as! EventTag, value: deletedEvent.unsignedEvent.id, tx: newTrans)
			}
			
			let kindInt = deletedEvent.unsignedEvent.kind.RAW_native() % 40_000
			if !NostrKindCategory.nonReplaceable.range.contains(kindInt) {
				var dTag:(any NOSTR_tag_value)? = nil
				if let tag = deletedEvent.unsignedEvent.tags.array.first(where: { $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "d") }) {
					dTag = tag.NOSTR_tag_values.array.first!
				}
				let replaceableKey = ReplaceableKey(pubkey: deletedEvent.unsignedEvent.publicKey, kind: deletedEvent.unsignedEvent.kind, dTag: dTag)
				let datedId = DatedID(date: deletedEvent.unsignedEvent.date, id: deletedEvent.unsignedEvent.id)
				
				try replaceableEvents.setEntry(key: replaceableKey, value: datedId, flags: [], tx: newTrans)
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
		do {
			let newTrans = try Transaction(env:env, readOnly:false)
			let (allFilterIds, _) = try getFilterEligibleIds(filters: filters, tx: newTrans)
			
			for id in allFilterIds {
				let deletedEvent = try signedEvents.loadEntry(key: id, tx: newTrans)
				try signedEvents.deleteEntry(key:id, tx:newTrans)
				
				// Remove Event from the indexes
				try authorIndex.deleteEntry(key: deletedEvent.unsignedEvent.publicKey, value: deletedEvent.unsignedEvent.id, tx: newTrans)
				
				try kindIndex.deleteEntry(key: deletedEvent.unsignedEvent.kind, value: deletedEvent.unsignedEvent.id, tx: newTrans)
				
				try dateIndex.deleteEntry(key: deletedEvent.unsignedEvent.date, value: deletedEvent.unsignedEvent.id, tx: newTrans)
				
				
				for tag in deletedEvent.unsignedEvent.tags.array {
					var dbTag = tag
					// Tags are indexed on their name and only the first item in the values array
					if tag.NOSTR_tag_values.array.count > 1 {
						dbTag.NOSTR_tag_values.array = [dbTag.NOSTR_tag_values.array.first!]
					}
					try tagIndex.deleteEntry(key: dbTag as! EventTag, value: deletedEvent.unsignedEvent.id, tx: newTrans)
				}
				
				let kindInt = deletedEvent.unsignedEvent.kind.RAW_native() % 40_000
				if !NostrKindCategory.nonReplaceable.range.contains(kindInt) {
					var dTag:(any NOSTR_tag_value)? = nil
					if let tag = deletedEvent.unsignedEvent.tags.array.first(where: { $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "d") }) {
						dTag = tag.NOSTR_tag_values.array.first!
					}
					let replaceableKey = ReplaceableKey(pubkey: deletedEvent.unsignedEvent.publicKey, kind: deletedEvent.unsignedEvent.kind, dTag: dTag)
					let datedId = DatedID(date: deletedEvent.unsignedEvent.date, id: deletedEvent.unsignedEvent.id)
					
					try replaceableEvents.setEntry(key: replaceableKey, value: datedId, flags: [], tx: newTrans)
				}
			}
			try newTrans.commit()
			log.info(Logger.Message.orange("successfully force deleted \(allFilterIds.count) events"))
		} catch {
			log.error(Logger.Message.red("Failed to delete events due to internal error."), metadata: ["error":"\(error)"])
		}
	}
}
