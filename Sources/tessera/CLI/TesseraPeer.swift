import Foundation
import NIO
import RAW
import RAW_dh25519
import RAW_base64
import bedrock_fifo
import wireguard_userspace_nio
import wireguard_crypto_core

/// A WireGuard peer that additionally carries a `tessera` role flag.
/// Conforms to the `PeerInformation` protocol so it can be handed directly
/// to the WireGuard interface, matching the stock `PeerInfo` type field-for-field
/// while adding `isTessera`.
///
/// When `isTessera` is true the peer is another Tessera instance, and the running
/// service will open a negentropy sync session with it. When false the peer is an
/// ordinary application (user) and only speaks NOSTR.
struct TesseraPeer: PeerInformation, Codable {
	/// The peer's public key.
	let publicKey: PublicKey
	/// The pre-shared key, or `nil` when not in use.
	let sharedKey: MemoryGuarded<SharedKey>?
	/// The IP address and port of the peer.
	let endpoint: Endpoint?
	/// The internal keep-alive of the peer, utilized by the keep-alive custom channel.
	let internalKeepAlive: TimeAmount?
	/// True if this peer is another Tessera instance (eligible for negentropy sync).
	let isTessera: Bool
	/// The data FIFO for incoming decrypted data from this peer.
	var inboundData: FIFO<ByteBuffer, Swift.Error>?

	/// Initializes a peer from an IP address and port.
	init(publicKey: PublicKey, sharedKey: MemoryGuarded<SharedKey>? = nil, ipAddress: String?, port: Int?, internalKeepAlive: TimeAmount?, isTessera: Bool, inboundData: FIFO<ByteBuffer, Swift.Error>? = nil) {
		self.publicKey = publicKey
		self.sharedKey = sharedKey
		self.internalKeepAlive = internalKeepAlive
		self.inboundData = inboundData
		self.isTessera = isTessera

		if (ipAddress != nil && port != nil) {
			do {
				self.endpoint = try Endpoint(SocketAddress(ipAddress: ipAddress!, port: port!))
			} catch {
				self.endpoint = nil
			}
		} else {
			self.endpoint = nil
		}
	}

	/// Initializes a peer from an `Endpoint`.
	init(publicKey: PublicKey, sharedKey: MemoryGuarded<SharedKey>? = nil, endpoint: Endpoint?, internalKeepAlive: TimeAmount?, isTessera: Bool, inboundData: FIFO<ByteBuffer, Swift.Error>? = nil) {
		self.publicKey = publicKey
		self.sharedKey = sharedKey
		self.endpoint = endpoint
		self.internalKeepAlive = internalKeepAlive
		self.inboundData = inboundData
		self.isTessera = isTessera
	}

	enum CodingKeys: String, CodingKey {
		case publicKey
		case sharedKey
		case endpoint
		case internalKeepAlive
		case isTessera
	}

	/// Decodes a peer from the given keyed container. The public and shared keys
	/// are stored as base64 strings. `isTessera` defaults to false when absent so
	/// that pre-existing configuration files remain decodable.
	init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)

		let endpoint  = try container.decodeIfPresent(Endpoint.self, forKey: .endpoint)
		let keepAlive = try container.decodeIfPresent(TimeAmount.self, forKey: .internalKeepAlive)
		let isTessera = try container.decodeIfPresent(Bool.self, forKey: .isTessera) ?? false
		let fifo = FIFO<ByteBuffer, Swift.Error>()

		let publicKeyString = try container.decode(String.self, forKey: .publicKey)
		let publicKeyBytes = try RAW_base64.decode(publicKeyString)
		guard publicKeyBytes.count == 32 else {
			throw DecodingError.dataCorruptedError(forKey: .publicKey, in: container, debugDescription: "Public key must be 32 bytes.")
		}
		let publicKey = RAW_dh25519.PublicKey(RAW_decode: publicKeyBytes.withUnsafeBytes { $0 })!

		let sharedKeyString = try container.decodeIfPresent(String.self, forKey: .sharedKey)
		guard let sharedKeyString = sharedKeyString else {
			self.init(publicKey: publicKey, sharedKey: nil, endpoint: endpoint, internalKeepAlive: keepAlive, isTessera: isTessera, inboundData: fifo)
			return
		}
		let bytes = try RAW_base64.decode(sharedKeyString)
		guard bytes.count == 32 else {
			throw DecodingError.dataCorruptedError(forKey: .sharedKey, in: container, debugDescription: "Shared key must be 32 bytes.")
		}
		let sharedKey = bytes.withUnsafeBufferPointer { ptr in
			return MemoryGuarded<SharedKey>.init(RAW_decode: UnsafeRawBufferPointer(ptr))
		}
		self.init(publicKey: publicKey, sharedKey: sharedKey, endpoint: endpoint, internalKeepAlive: keepAlive, isTessera: isTessera, inboundData: fifo)
	}

	/// Encodes the peer into the given keyed container, storing the public and
	/// shared keys as base64 strings.
	func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)
		let publicKeyString = String(RAW_base64.encode(publicKey))
		let sharedKeyString = sharedKey == nil ? nil : String(RAW_base64.encode(sharedKey!))
		try container.encode(publicKeyString, forKey: .publicKey)
		try container.encodeIfPresent(sharedKeyString, forKey: .sharedKey)
		try container.encodeIfPresent(endpoint, forKey: .endpoint)
		try container.encodeIfPresent(internalKeepAlive, forKey: .internalKeepAlive)
		try container.encode(isTessera, forKey: .isTessera)
	}
}
