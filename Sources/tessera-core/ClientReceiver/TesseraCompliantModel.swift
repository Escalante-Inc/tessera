import Foundation
import nostr_kit_swift
import RAW

/// This protocol defines a model that can converse with the Tesserae.
/// If a model doesn't conform to this protocol, it is not allowed to connect to the TesseraPipeline.
/// The model transfers Nostr messages for a specified event content type.
public protocol TesseraCompliantModel {
	associatedtype ContentType: NOSTR_event_content
	
	/// Primary storage of the UnsignedEvents.
	/// The ONLY place a cached copy of the UnsignedEvent should be stored.
	/// Stores ALL UnsignedEvents caught by the filter including event history.
	var modelStorage: [NOSTR_id : UnsignedEvent<ContentType>] { get set }
	
	/// An index for up the up to date events of type ContentType.
	/// Indexed by the event's replaceable key.
	var latestByReplaceableKey: [ReplaceableKey : NOSTR_id] { get set }
	
	/// An index for the full history of events of type ContentType.
	/// Indexed by the event's replaceable key.
	var historyByReplaceableKey: [ReplaceableKey : [NOSTR_id]] { get set }
	
	/// The subscription id(s) for the filter(s) used to fetch the events for this storage.
	var subscriptionIDs: [String] { get set }
}

extension TesseraCompliantModel {
	
	public func latestEvents() -> [UnsignedEvent<ContentType>] {
		latestByReplaceableKey.compactMap { modelStorage[$0.value] }
	}
	
	public mutating func clearCache() {
		modelStorage = [:]
		latestByReplaceableKey = [:]
		historyByReplaceableKey = [:]
	}
	
	public mutating func delete(id: NOSTR_id) throws {
		guard let event = modelStorage[id] else {
			return
		}
		modelStorage.removeValue(forKey: id)
		let key = try ReplaceableKey(event: event)
		guard var history = historyByReplaceableKey[key] else {
			return
		}
		history.removeAll { $0 == id }
		guard !history.isEmpty else {
			latestByReplaceableKey.removeValue(forKey: key)
			return
		}
		guard let latestId = latestByReplaceableKey[key], latestId == id else {
			return
		}
		var latestDate = Date.distantPast
		var currentLatestId:NOSTR_id?
		for i in history.indices {
			if let e = modelStorage[history[i]], e.date.currentDate() > latestDate {
				latestDate = e.date.currentDate()
				currentLatestId = history[i]
			}
		}
		latestByReplaceableKey[key] = currentLatestId
	}
	
	public mutating func decodeEventAndUpsert(ptr: UnsafeRawBufferPointer) throws{
		guard let msg = NOSTR_message_EVENT<UnsignedEvent<ContentType>>(RAW_decode: ptr.baseAddress!, count: ptr.count) else {
			throw NOSTR_message_error.badDecode
		}
		guard subscriptionIDs.contains(String(msg.subscriptionID)) else {
			throw NOSTR_message_error.badSubscriptionID
		}
//		guard msg.event.isValidSignature() else {
//			throw NOSTR_message_error.badDecode
//		}
		let event = msg.event.unsignedEvent
		
		let id = event.id
		let key = try ReplaceableKey(event: event)

		modelStorage[id] = event

		func insertSorted(_ id: NOSTR_id, for key: ReplaceableKey, eventDate: NOSTR_date) {
			var history = historyByReplaceableKey[key, default: []]
			var insertIndex = history.count
			for (i, existingID) in history.enumerated() {
				if existingID == id {
					return
				}
				if let existingEvent = modelStorage[existingID],
				   existingEvent.date > eventDate {
					insertIndex = i
					break
				}
			}
			history.insert(id, at: insertIndex)
			historyByReplaceableKey[key] = history
		}
		
		if let latestId = latestByReplaceableKey[key], let latestEvent = modelStorage[latestId], latestEvent.date >= event.date {
			// New event is newer than the current latest event.
			insertSorted(id, for: key, eventDate: event.date)
		} else {
			latestByReplaceableKey[key] = id
			insertSorted(id, for: key, eventDate: event.date)
		}
	}
}
