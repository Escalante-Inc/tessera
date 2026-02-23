import Logging
import Foundation
import RAW
import RAW_dh25519
import RAW_ed25519
import NIO
import nostr_kit_swift

public func eventMatchesFilters<Content:NOSTR_event_content>(_ event: NOSTR_event_signed<UnsignedEvent<Content>>, filters: [Filter], logLevel: Logger.Level) -> Bool {
	var logger = Logger(label: "filter")
	logger.logLevel = logLevel
	guard !filters.isEmpty else {
		return true
	}
	for filter in filters {
		if filter.apply(to: event) {
			return true
		}
		logger.trace("Event doesn't match filter, moving to next filter...")
	}
	logger.trace("Event doesn't match any filter", metadata: ["event_id": "\(String(describing: event.unsignedEvent.id))"])
	return false
}

internal func createNewUpdatedEvent<Content:NOSTR_event_content>(_ event: NOSTR_event_signed<UnsignedEvent<Content>>, authorSigningKey:MemoryGuarded<Ed25519.PrivateKey>, admin: MemoryGuarded<PrivateKey>, newDate: NOSTR_date?, addTags: [any NOSTR_tag]?, removeTags: [any NOSTR_tag]?, overwriteTags: [any NOSTR_tag]?, kind: NOSTR_kind?, content: Content?) throws -> NOSTR_event_signed<UnsignedEvent<Content>> {
	let eventDate = newDate ?? event.unsignedEvent.date
	let eventKind = kind ?? event.unsignedEvent.kind
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
	eventTags.append(try createAdminTag(admin: admin))
	let unsignedEvent = try UnsignedEvent(publicKey: event.unsignedEvent.publicKey, date: eventDate, tags: eventTags, kind: eventKind, content: eventContent)
	return try unsignedEvent.sign(as: authorSigningKey)
}

internal func createAdminTag(admin: MemoryGuarded<PrivateKey>) throws -> EventTag {
	let (edPubKey, _) = try Ed25519.generateKeys(secretKey: admin)
	let dateChanged = NOSTR_date(date: Date())
	let tagNameString = "admin"
	let tagName = tagNameString.data(using: .utf8)!.withUnsafeBytes { ptr in
		NOSTR_tag_name(RAW_staticbuff: ptr.baseAddress!)
	}
	return try EventTag(NOSTR_tag_index_field: tagName, NOSTR_tag_values: [edPubKey, dateChanged])
}
