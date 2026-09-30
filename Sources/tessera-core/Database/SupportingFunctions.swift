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
	   (filter.authors == [] || filter.authors.contains(event.unsignedEvent.publicKey)) &&
	   (filter.applications == [] || filter.applications.contains(event.unsignedEvent.application)) &&
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

