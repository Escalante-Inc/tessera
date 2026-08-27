import nostr_kit_swift
import NIO

/// A concrete `TesseraClientReceiver` whose storage is pre-declared, so client
/// applications do not need to re-implement the four backing stores by hand.
///
/// Subclass to add application-specific behavior, or instantiate it directly and
/// attach `TesseraCompliantModel`s:
///
///     let receiver = TesseraClientReceiverStore()
///     receiver.models.append(myModel)
open class TesseraClientReceiverStore: TesseraClientReceiver {
	/// An index of the most recently seen `NOSTR_id` for each replaceable key.
	open var references: [ReplaceableKey : NOSTR_id] = [:]

	/// A map of deleted event ids to the date of their deletion event.
	open var deletionEventIds: [NOSTR_id : NOSTR_date] = [:]

	/// Filters that still need to be requested from the server, keyed by subscription id.
	open var referenceNeeds: [String : [Filter]] = [:]

	/// The models that inbound events are decoded into.
	open var models: [any TesseraCompliantModel] = []

	/// Creates an empty receiver.
	public init() {}
}
