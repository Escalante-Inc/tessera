import nostr_kit_swift
import NIO

public protocol TesseraClientReceiver {
	var references: [ReplaceableKey : NOSTR_id] { get set }
	var deletionEventIds: [NOSTR_id : NOSTR_date] { get set }
	var referenceNeeds: [String : [Filter]] { get set }
	var models: [any TesseraCompliantModel] { get set }
}

extension TesseraClientReceiver {
	// Initially decodes the message so that we can see the id, kind, tags, ...
	public func decode(ptr: UnsafeRawBufferPointer) throws -> NOSTR_message_EVENT<UnsignedEvent<ByteBuffer>> {
		guard let msg = NOSTR_message_EVENT<UnsignedEvent<ByteBuffer>>(RAW_decode: ptr) else {
			throw NOSTR_message_error.badDecode
		}
//		guard msg.event.isValidSignature() else {
//			throw NOSTR_message_error.badDecode
//		}
		return msg
	}
	
	mutating func handleDeletion(_ event: UnsignedEvent<ByteBuffer>, replaceableKey: ReplaceableKey) throws {
		for tag in event.tags.array {
			guard let eventRefTag = tag.unwrap(as: EventRefTag.self) else { continue }
			let id = eventRefTag.value
			
			deletionEventIds[id] = event.date
			
			for i in models.indices {
				try models[i].delete(id: id)
			}
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
			try handleDeletion(event, replaceableKey: replaceableKey)
			return
		}
		
		// Checking for reference event tags
		// Puts all reference filters into an array (per model)
		// All filters can be sent in one REQ (per model)
		for tag in event.tags.array {
			guard let name = tag.name else { continue }
			guard let rkTag = tag.unwrap(as: ReplaceableKeyTag.self) else { continue }
			for model in models {
				if model.subscriptionIDs.contains(name) {
					let key = rkTag.value
					if model.latestByReplaceableKey[key] == nil {
						let authors = key.pubkey == nil ? [] : [key.pubkey!]
						let dtag = key.dTag == nil ? [] : [key.dTag!]
						referenceNeeds[name, default: []].append(Filter(authors: authors, kinds: [key.kind], tags: dtag))
					}
				}
			}
		}
				
		for i in models.indices {
			if models[i].subscriptionIDs.contains(String(byteBufferMsg.subscriptionID)) {
				do {
					try models[i].decodeEventAndUpsert(ptr: ptr)
				} catch {
					throw NOSTR_message_error.badDecode
				}
			}
		}
	}
}
