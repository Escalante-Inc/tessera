import nostr_kit_swift
import NIO

public protocol TesseraClientReceiver {
	// An event could be in two or more tessera compliant models
	// and also just show up once in the replaceable events.
	// When removing an event, remove it from ALL tessera compliant models and the replaceable events.
	// When removing a tessera compliant model, before deleting everything in the model,
	// make sure to remove anything in replaceable events that IS NOT being used in a different
	// tessera compliant model.
	var replaceableEvents: [ReplaceableKey : (id: NOSTR_id, date: NOSTR_date)] { get set }
	var deletionEventIds: [NOSTR_id : NOSTR_date] { get set }
	var eventSubscriptions: [NOSTR_id : Set<String>] { get set }
	
	// 1-1 relationship between a subscription id and tessera compliant model
	// 1-1 relationship between a filter request and a tessera compliant model
	var models: [String: any TesseraCompliantModel] { get set }
	
}

extension TesseraClientReceiver {
	// Initially decodes the message so that we can see the id, kind, tags, ...
	public func decode(ptr: UnsafeRawBufferPointer) throws -> NOSTR_message_EVENT<UnsignedEvent<ByteBuffer>> {
		guard let msg = NOSTR_message_EVENT<UnsignedEvent<ByteBuffer>>(RAW_decode: ptr.baseAddress!, count: ptr.count) else {
			throw NOSTR_message_error.badDecode
		}
		if(msg.event.isValidSignature()) {
			return msg
		} else {
			throw NOSTR_message_error.badDecode
		}
	}
	
	mutating func handleDeletion(_ event: UnsignedEvent<ByteBuffer>, replaceableKey: ReplaceableKey) {
		for tag in event.tags.array {
			guard tag.NOSTR_tag_index_field == NOSTR_tag_name(string: "e") else { continue }
			
			let id = tag.NOSTR_tag_values.array.first!.RAW_access { ptr in
				return NOSTR_id(RAW_staticbuff: ptr.baseAddress!)
			}
			
			deletionEventIds[id] = event.date
			
			for i in models.values.indices {
				models.values[i].removeFromLocalStorage(event.id)
			}

			eventSubscriptions.removeValue(forKey: event.id)
			replaceableEvents.removeValue(forKey: replaceableKey)
		}
	}
	
	public mutating func receive(ptr: UnsafeRawBufferPointer) throws {
		let byteBufferMsg = try decode(ptr: ptr)
		
		let event = byteBufferMsg.event.unsignedEvent
		
		// Ignore event if it's deleted
		if let deletedDate = deletionEventIds[event.id] {
			if deletedDate >= event.date {
				return
			}
		}
		
		let replaceableKey = try ReplaceableKey(event: event)
		
		if event.kind.RAW_native() == 5 {
			handleDeletion(event, replaceableKey: replaceableKey)
			return
		}
		
		if let replaceEventTime = replaceableEvents[replaceableKey] {
			if replaceEventTime.date > event.date {
				return
			} else if replaceEventTime.id > event.id {
				return
			} else {
				// New event is newer than the one stored.
				models[String(byteBufferMsg.subscriptionID)]?.removeFromLocalStorage(replaceEventTime.id)
			}
		}
		// Overwrite/write replaceableEvents[replaceableKey] with this incoming event
		eventSubscriptions[event.id]?.insert(String(byteBufferMsg.subscriptionID))
		replaceableEvents[replaceableKey] = (event.id, event.date)
		
		if models[String(byteBufferMsg.subscriptionID)] != nil {
			do {
				try models[String(byteBufferMsg.subscriptionID)]!.decodeEventAndStore(ptr: ptr)
			} catch {
				throw NOSTR_message_error.badDecode
			}
		}
	}
	
	/// Removes the current cache of data associated with the model for the given subscription ID.
	/// Does not remove cached data if the data is associated with other models.
	public mutating func removeCach(for subscriptionID: String) {
		guard models[subscriptionID] != nil else { return }
		for id in models[subscriptionID]!.storageIds() {
			guard eventSubscriptions[id] != nil else { continue }
			if eventSubscriptions[id]!.count > 1 {
				eventSubscriptions[id]!.remove(subscriptionID)
			} else {
				eventSubscriptions.removeValue(forKey: id)
//				replaceableEvents.removeAll { $0.value.id == id }
			}
		}
		
		models[subscriptionID]!.clearLocalStorage()
	}
}
