import Foundation
import nostr_kit_swift
import RAW

/// A generic `TesseraCompliantModel` whose storage is pre-declared, so a data model
/// only needs to declare its content type and configure its subscription ids:
///
///     final class MyModel: TesseraModel<MyContent> {
///         override var subscriptionIDs: [String] { ["my-subscription"] }
///     }
open class TesseraModel<ContentType: NOSTR_event_content>: TesseraCompliantModel {
	/// Primary storage of the cached `UnsignedEvent`s.
	open var modelStorage: [NOSTR_id : UnsignedEvent<ContentType>] = [:]

	/// An index of the up-to-date event of `ContentType`, keyed by replaceable key.
	open var latestByReplaceableKey: [ReplaceableKey : NOSTR_id] = [:]

	/// An index of the full history of events of `ContentType`, keyed by replaceable key.
	open var historyByReplaceableKey: [ReplaceableKey : [NOSTR_id]] = [:]

	/// The subscription id(s) for the filter(s) used to fetch this model's events.
	open var subscriptionIDs: [String] = []

	/// Creates an empty model.
	public init() {}
}
