import Logging
import Foundation
import RAW
import RAW_dh25519
import RAW_ed25519
import NIO
import nostr_kit_swift

/// Creates a `NOSTR_kind` inside the range of the access level with a value of kind
public func createKind(accessLevel: UInt8, kind:UInt32) -> NOSTR_kind {
	let kind = kind % 40_000
	return NOSTR_kind(RAW_native: (UInt32(accessLevel) + 1) * 40_000 + kind)
}

public func applyTesseraFilter<Content:NOSTR_event_content>(_ event: NOSTR_event_signed<UnsignedEvent<Content>>, filter: Filter) -> Bool {
	var hasTags: Bool = true
	tagLoop: for tag in filter.tags {
		for eventTag in event.unsignedEvent.tags.array {
			guard tag.indexField == eventTag.indexField else {
				continue
			}
			// At least one value from the event must appear in the filter values
			if tag.value.isEqual(to: eventTag.value) {
				continue tagLoop
			}
		}
		hasTags = false
	}
	if((filter.ids == [] || filter.ids.contains(event.unsignedEvent.id)) &&
	   (filter.authors == [] || filter.authors.contains(event.unsignedEvent.publicKey) || filter.authors.contains(author(ofEvent: event))) &&
	   (filter.kinds == [] || filter.kinds.contains(event.unsignedEvent.kind)) &&
	   (filter.since == nil || filter.since! <= event.unsignedEvent.date) &&
	   (filter.until == nil || filter.until! >= event.unsignedEvent.date) &&
	   hasTags) {
		return true
	}
	return false
}

public func eventMatchesFilters<Content:NOSTR_event_content>(_ event: NOSTR_event_signed<UnsignedEvent<Content>>, filters: [Filter], logLevel: Logger.Level) -> Bool {
	var logger = Logger(label: "filter")
	logger.logLevel = logLevel
	guard !filters.isEmpty else {
		return true
	}
	for filter in filters {
		if applyTesseraFilter(event, filter: filter) {
			return true
		}
		logger.trace("Event doesn't match filter, moving to next filter...")
	}
	logger.trace("Event doesn't match any filter", metadata: ["event_id": "\(String(describing: event.unsignedEvent.id))"])
	return false
}

public func author<Content:NOSTR_event_content>(ofEvent event: NOSTR_event_signed<UnsignedEvent<Content>>) -> PublicKey {
//	let tagNameString = "author"
//	let tagName = tagNameString.data(using: .utf8)!.withUnsafeBytes { ptr in
//		NOSTR_tag_name(RAW_staticbuff: ptr.baseAddress!)
//	}
//	for tag in event.unsignedEvent.tags.array {
//		if tag.NOSTR_tag_index_field == tagName {
//			return tag.NOSTR_tag_values.array.first! as! PublicKey
//		}
//	}
	return event.unsignedEvent.publicKey
}

internal func createNewUpdatedEvent<Content:NOSTR_event_content>(_ event: NOSTR_event_signed<UnsignedEvent<Content>>, adminSigningKey:MemoryGuarded<Ed25519.PrivateKey>, addTags: [any NOSTR_tag]?, removeTags: [any NOSTR_tag]?, overwriteTags: [any NOSTR_tag]?, content: Content?) throws -> NOSTR_event_signed<UnsignedEvent<Content>> {
	let eventContent = content ?? event.unsignedEvent.content
	var eventTags: [any NOSTR_tag] = []
	if let overwriteTags {
		eventTags = overwriteTags
	} else {
		eventTags = event.unsignedEvent.tags.array
		if let addTags, !addTags.isEmpty {
			for tag in addTags {
				if !eventTags.contains(where: { $0.isEqual(to: tag) }) {
					eventTags.append(tag)
				}
			}
		}
		if let removeTags, !removeTags.isEmpty {
			eventTags.removeAll { existingTag in
				removeTags.contains(where: { $0.isEqual(to: existingTag) })
			}
		}
	}
//	eventTags.append(try createAuthorTag(author: event.unsignedEvent.publicKey))
	let unsignedEvent = try UnsignedEvent(publicKey: event.unsignedEvent.publicKey, date: NOSTR_date(date: Date()), tags: eventTags, application: NOSTR_application(RAW_native: 1), kind: event.unsignedEvent.kind, content: eventContent)
	return try unsignedEvent.sign(as: adminSigningKey)
}

//internal func createAuthorTag(author: PublicKey) throws -> EventTag {
//	let dateChanged = NOSTR_date(date: Date())
//	let tagNameString = "author"
//	let tagName = tagNameString.data(using: .utf8)!.withUnsafeBytes { ptr in
//		NOSTR_tag_name(RAW_staticbuff: ptr.baseAddress!)
//	}
//	return EventTag(indexField: tagName, value: <#T##EventTag.tagValueType#>)
//}
