import NIO
import RAW
import RAW_dh25519
import QuickLMDB
import bedrock_fifo
import wireguard_userspace_nio
import concord

/// `ConcordTransport` implementation over the tessera WireGuard channel and a
/// per-peer sync FIFO.
///
/// `send` frames one message per datagram and writes it straight out the
/// shared channel (the same path the NOSTR protocol uses); `receive` blocks on
/// the peer's sync FIFO — the per-peer task routes inbound "NEGT" frames into
/// it — and returns `nil` only when the FIFO is closed (orderly end).
///
/// The transport is a value that is handed into the round thread: the channel,
/// FIFO, and public key are all `Sendable`, and the round never crosses
/// threads mid-message.
public struct ConcordWGTransport<Key: ConcordKey, Value: MDB_convertible>: ConcordTransport {
	let channel: Channel
	let peerPublicKey: PublicKey
	let syncFIFO: FIFO<ByteBuffer, Swift.Error>

	public init(channel: Channel, peerPublicKey: PublicKey, syncFIFO: FIFO<ByteBuffer, Swift.Error>) {
		self.channel = channel
		self.peerPublicKey = peerPublicKey
		self.syncFIFO = syncFIFO
	}

	public func send(_ message: ConcordMessage<Key, Value>) throws {
		let frame = try ConcordWireCodec.encode(message)
		try WGInterface<KCPChannels>.write(channel: channel, publicKey: peerPublicKey, data: frame)
	}

	public func receive() throws -> ConcordMessage<Key, Value>? {
		// Blocking consumer: the round runs on its own dedicated thread, so it
		// is safe to park here until a frame arrives or the FIFO closes.
		let consumer = syncFIFO.makeSyncConsumerBlocking()
		guard let frame = try consumer.next() else {
			return nil
		}
		return try ConcordWireCodec.decode(frame)
	}

	public func close() throws {
		// The FIFO and channel are owned by the service and outlive the round.
	}
}
