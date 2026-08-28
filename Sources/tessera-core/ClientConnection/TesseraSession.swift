import Foundation
import Logging
import NIO
import nostr_kit_swift
import RAW
import RAW_dh25519
import RAW_ed25519

/// A high-level session that composes a `TesseraClient` connection with a
/// `TesseraClientReceiver` and the NOSTR message protocol.
///
/// `TesseraSession` hides the wire message types from application code: subscribe
/// with `subscribe(subscriptionID:filters:)`, publish with `publish(_:)`, and close
/// with `unsubscribe(subscriptionID:)`. Inbound server messages are decoded with
/// `NOSTR_message.decode` and dispatched to the attached receiver (events) or to the
/// `onNotice` / `onEOSE` / `onOK` callbacks.
public final class TesseraSession: @unchecked Sendable {
	/// The underlying connection to the server.
	public let client: TesseraClient

	/// The receiver that inbound events are decoded into.
	public var receiver: TesseraClientReceiverStore

	/// The application id this client belongs to.
	public let application: UInt16

	/// The Nostr public key used to sign requests to the server.
	public let myNostrPublicKey: PublicKey

	/// Called when the server sends a NOTICE message.
	public var onNotice: (@Sendable (String) -> Void)?

	/// Called when the server signals end-of-stored-events (EOSE) for a subscription.
	public var onEOSE: (@Sendable (NOSTR_message_EOSE) -> Void)?

	/// Called when the server acknowledges a published event (OK).
	public var onOK: (@Sendable (NOSTR_message_OK) -> Void)?

	private let logger: Logger

	/// Creates a session from a connection, receiver, application id, and Nostr public key.
	public init(client: TesseraClient,
				receiver: TesseraClientReceiverStore = TesseraClientReceiverStore(),
				application: UInt16,
				myNostrPublicKey: PublicKey,
				logLevel: Logger.Level = .info) {
		self.client = client
		self.receiver = receiver
		self.application = application
		self.myNostrPublicKey = myNostrPublicKey
		var makeLogger = Logger(label: "tessera-session")
		makeLogger.logLevel = logLevel
		self.logger = makeLogger
	}

	/// Establishes the connection and wires inbound data into the receiver.
	public func connect() async throws {
		client.onReceive = { [weak self] ptr in
			self?.handleInbound(ptr)
		}
		try await client.connect()
	}

	/// Tears down the connection.
	public func disconnect() async {
		client.onReceive = nil
		await client.disconnect()
	}

	/// Subscribes to events matching the given filters.
	///
	/// The server will begin sending matching events under `subscriptionID` until a
	/// `CLOSE` is sent for that id.
	public func subscribe(subscriptionID: String, filters: [Filter]) async throws {
		let request = NOSTR_message_REQ(subscriptionID: subscriptionID, filters: filters, from: myNostrPublicKey, fetchHistory: true)
		try await client.write(request)
	}

	/// Ends a previously issued subscription.
	public func unsubscribe(subscriptionID: String) async throws {
		let close = NOSTR_message_CLOSE(subscriptionID: subscriptionID)
		try await client.write(close)
	}

	/// Publishes a signed event to the server.
	public func publish(_ event: NOSTR_event_signed<UnsignedEvent<ByteBuffer>>) async throws {
		let message = NOSTR_message_EVENT(subscriptionID: "", event: event)
		try await client.write(message)
	}

	/// Builds, signs, and publishes an event with the given content, kind, and tags.
	///
	/// This is the sheltered counterpart to `delete(eventID:signedBy:)`: it replaces
	/// hand-assembling `UnsignedEvent<ByteBuffer>`, `ByteBuffer(string:)`, `DTag(value:)`,
	/// and `NOSTR_date` in application code. The session's own public key and application
	/// id are used, the event is dated now, the id is computed from the fields, and the
	/// event is signed with the supplied Nostr private key before being sent.
	///
	/// The content is generic over `NOSTR_event_content`, so any RAW-encodable payload
	/// works — `ByteBuffer`, a custom `@RAW_convertible_string_type` type, or (via the
	/// `String` overload below) plain text.
	public func publish<ContentType: NOSTR_event_content>(
		content: ContentType,
		kind: UInt32,
		tags: [any NOSTR_tag] = [],
		signedBy myNostrPrivateKey: MemoryGuarded<RAW_ed25519.PrivateKey>
	) async throws {
		let signedEvent = try makeSignedEvent(content: content, kind: kind, tags: tags, signedBy: myNostrPrivateKey)
		try await writeSignedEvent(signedEvent)
	}

	/// Convenience overload of `publish(content:kind:tags:signedBy:)` for the most
	/// common case: a plain `String`, wrapped into a `ByteBuffer` automatically.
	public func publish(
		content: String,
		kind: UInt32,
		tags: [any NOSTR_tag] = [],
		signedBy myNostrPrivateKey: MemoryGuarded<RAW_ed25519.PrivateKey>
	) async throws {
		let signedEvent = try makeSignedEvent(content: ByteBuffer(string: content), kind: kind, tags: tags, signedBy: myNostrPrivateKey)
		try await writeSignedEvent(signedEvent)
	}

	/// Builds and signs an event (dated now) without sending it.
	internal func makeSignedEvent<ContentType: NOSTR_event_content>(
		content: ContentType,
		kind: UInt32,
		tags: [any NOSTR_tag],
		signedBy myNostrPrivateKey: MemoryGuarded<RAW_ed25519.PrivateKey>
	) throws -> NOSTR_event_signed<UnsignedEvent<ContentType>> {
		let unsigned = try UnsignedEvent<ContentType>(publicKey: myNostrPublicKey, tags: tags, application: application, kind: kind, content: content
		)
		return try unsigned.sign(as: myNostrPrivateKey)
	}

	/// Encodes a signed event as an EVENT message and writes it to the server.
	private func writeSignedEvent<ContentType: NOSTR_event_content>(_ signedEvent: NOSTR_event_signed<UnsignedEvent<ContentType>>) async throws {
		let message = NOSTR_message_EVENT(subscriptionID: "", event: signedEvent)
		try await client.write(message)
	}

	/// Builds, signs, and publishes a deletion event (kind 5) for the given event id.
	/// - Throws: any error from event construction or signing.
	public func delete(eventID: NOSTR_id, signedBy myNostrPrivateKey: MemoryGuarded<RAW_ed25519.PrivateKey>) async throws {
		let unsigned = try UnsignedEvent<ByteBuffer>(publicKey: myNostrPublicKey,
													 tags: [EventRefTag(value: eventID)],
													 application: application,
													 kind: 5,
													 content: ByteBuffer())
		let deletionEvent = try unsigned.sign(as: myNostrPrivateKey)
		try await publish(deletionEvent)
	}

	/// Decodes inbound bytes and dispatches them to the receiver or the callbacks.
	private func handleInbound(_ ptr: UnsafeRawBufferPointer) {
		guard let message = NOSTR_message<UnsignedEvent<ByteBuffer>>.decode(ptr) else {
			logger.debug("Inbound data did not match any known NOSTR message type.")
			return
		}
		switch message {
			case .EVENT:
				do {
					try receiver.receive(ptr: ptr)
				} catch {
					logger.debug("Failed to process inbound event: \(error)")
				}
			case .NOTICE(let notice):
				logger.info("Server notice: \(notice.noticeText)")
				onNotice?(notice.noticeText)
			case .EOSE(let eose):
				onEOSE?(eose)
			case .OK(let ok):
				onOK?(ok)
			case .REQ, .CLOSE:
				// Client avatars do not receive REQ or CLOSE messages from the server.
				break
		}
	}
}
