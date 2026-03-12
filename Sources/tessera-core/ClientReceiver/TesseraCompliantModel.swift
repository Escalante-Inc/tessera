import nostr_kit_swift
import RAW

/// This protocol defines a model that can converse with the Tesserae.
/// If a model doesn't conform to this protocol, it is not allowed to connect to the TesseraPipeline.
/// The model transfers Nostr messages for a specified event content type.
public protocol TesseraCompliantModel {
	associatedtype ContentType: NOSTR_event_content
	var modelStorage: [NOSTR_id : UnsignedEvent<ContentType>] { get set }
	var subscriptionID: String { get }
}

extension TesseraCompliantModel {
	public func storageIds() -> [NOSTR_id] {
		return modelStorage.keys.map { $0 }
	}
	
	public mutating func clearLocalStorage() {
		modelStorage = [:]
	}
	
	// Removes an event from the storage that has either been updated or deleted.
	public mutating func removeFromLocalStorage(_ id: NOSTR_id) {
		modelStorage.removeValue(forKey: id)
	}
	
	// Adds a new event to the storage
	public mutating func decodeEventAndStore(ptr: UnsafeRawBufferPointer) throws{
		guard let msg = NOSTR_message_EVENT<UnsignedEvent<ContentType>>(RAW_decode: ptr.baseAddress!, count: ptr.count) else {
			throw NOSTR_message_error.badDecode
		}
		guard subscriptionID == String(msg.subscriptionID) else {
			throw NOSTR_message_error.badSubscriptionID
		}
		if(msg.event.isValidSignature()) {
			modelStorage[msg.event.unsignedEvent.id] = msg.event.unsignedEvent
		} else {
			throw NOSTR_message_error.badDecode
		}
	}
}
