import Foundation
import Logging
import NIO
import bedrock_fifo
import RAW
import RAW_dh25519
import RAW_base64
import wireguard_userspace_nio

/// The connection settings used to reach a single Tessera server.
public struct TesseraClientConfiguration: Sendable {
	/// The IP address or hostname of the server.
	public let serverIP: String
	/// The server's WireGuard listening port.
	public let serverPort: Int
	/// The server's WireGuard public key (the peer this client connects to).
	public let serverPublicKey: RAW_dh25519.PublicKey
	/// This client's own WireGuard private key. The server must list the matching
	/// public key in its peer configuration.
	public let myPrivateKey: MemoryGuarded<RAW_dh25519.PrivateKey>
	/// The WireGuard MTU. Defaults to `1400`.
	public let mtu: UInt16
	/// The log level for the underlying WireGuard interface.
	public let logLevel: Logger.Level

	/// Creates a configuration from a server address and a WireGuard key pair.
	public init(serverIP: String,
				serverPort: Int,
				serverPublicKey: RAW_dh25519.PublicKey,
				myPrivateKey: MemoryGuarded<RAW_dh25519.PrivateKey>,
				mtu: UInt16 = 1400,
				logLevel: Logger.Level = .info) {
		self.serverIP = serverIP
		self.serverPort = serverPort
		self.serverPublicKey = serverPublicKey
		self.myPrivateKey = myPrivateKey
		self.mtu = mtu
		self.logLevel = logLevel
	}

	/// Creates a configuration from base64-encoded WireGuard keys.
	///
	/// Returns `nil` if either key is not exactly 32 bytes of base64 data.
	public init?(serverIP: String,
				 serverPort: Int,
				 serverPublicKeyBase64: String,
				 myPrivateKeyBase64: String,
				 mtu: UInt16 = 1400,
				 logLevel: Logger.Level = .info) {
		guard let serverRaw = try? RAW_base64.decode(serverPublicKeyBase64), serverRaw.count == 32 else { return nil }
		guard let myRaw = try? RAW_base64.decode(myPrivateKeyBase64), myRaw.count == 32 else { return nil }
		let serverKey = RAW_dh25519.PublicKey(RAW_decode: serverRaw.withUnsafeBytes { $0 })!
		guard let myKey = myRaw.withUnsafeBufferPointer({ ptr in MemoryGuarded<RAW_dh25519.PrivateKey>.init(RAW_decode: UnsafeRawBufferPointer(ptr)) }) else { return nil }
		self.init(serverIP: serverIP, serverPort: serverPort, serverPublicKey: serverKey, myPrivateKey: myKey, mtu: mtu, logLevel: logLevel)
	}
}

/// An error thrown by `TesseraClient`.
public enum TesseraClientError: Swift.Error {
	/// The client is not connected to a server.
	case notConnected
	/// The underlying WireGuard interface reported an error.
	case writeFailed(any Swift.Error)
}

/// A ready-made WireGuard client connection to a single Tessera server.
///
/// `TesseraClient` owns the entire connection lifecycle: it creates the WireGuard
/// interface, waits for the UDP channel to bind, drains the peer's inbound FIFO,
/// and exposes a simple `write(_:)` that RAW-encodes any message into the tunnel.
///
/// Assign `onReceive` before calling `connect()` to receive each inbound plaintext
/// datagram from the server.
public final class TesseraClient: @unchecked Sendable {
	/// The connection settings used to establish the tunnel.
	public let configuration: TesseraClientConfiguration

	/// Called for every inbound plaintext datagram received from the server.
	/// The pointer is only valid for the duration of the call.
	public var onReceive: ((UnsafeRawBufferPointer) -> Void)?

	/// Whether the client currently has an active WireGuard interface.
	public private(set) var isConnected: Bool = false

	private let logger: Logger
	private let state = LockedState(ClientState())

	private struct ClientState {
		var interface: WGInterface<KCPChannels>?
		var connectionTask: Task<Void, Never>?
		var consumerTask: Task<Void, Never>?
		var peerFIFO: FIFO<ByteBuffer, Swift.Error>?
	}

	/// Creates a client from an existing configuration.
	public init(configuration: TesseraClientConfiguration) {
		self.configuration = configuration
		var makeLogger = Logger(label: "tessera-client")
		makeLogger.logLevel = configuration.logLevel
		self.logger = makeLogger
	}

	/// Creates a client from a server address and a WireGuard key pair.
	public convenience init(serverIP: String,
							serverPort: Int,
							serverPublicKey: RAW_dh25519.PublicKey,
							myPrivateKey: MemoryGuarded<RAW_dh25519.PrivateKey>,
							mtu: UInt16 = 1400,
							logLevel: Logger.Level = .info) {
		self.init(configuration: TesseraClientConfiguration(
			serverIP: serverIP, serverPort: serverPort,
			serverPublicKey: serverPublicKey, myPrivateKey: myPrivateKey,
			mtu: mtu, logLevel: logLevel))
	}

	/// Establishes the WireGuard tunnel to the server.
	///
	/// Starts the interface, waits for the UDP channel to bind, and begins draining
	/// the peer's inbound FIFO into `onReceive`. Safe to call once; subsequent calls
	/// while already connected are ignored.
	public func connect() async throws {
		let existing = state.withLock { $0.interface }
		guard existing == nil else { return }

		let fifo = FIFO<ByteBuffer, Swift.Error>()
		let peerInfo = PeerInfo(
			publicKey: configuration.serverPublicKey,
			sharedKey: nil,
			ipAddress: configuration.serverIP,
			port: configuration.serverPort,
			internalKeepAlive: nil,
			inboundData: fifo
		)
		let myInterface = try WGInterface<KCPChannels>(
			staticPrivateKey: configuration.myPrivateKey,
			mtu: configuration.mtu,
			initialConfiguration: [peerInfo],
			logLevel: configuration.logLevel,
			listeningPort: 0
		)
		state.withLock { $0.interface = myInterface; $0.peerFIFO = fifo }

		// Run the interface as a Service on a background task.
		let connectionTask = Task { [weak self, myInterface] in
			do {
				try await myInterface.run()
			} catch {
				self?.logger.error("TesseraClient interface stopped: \(error)")
			}
		}
		state.withLock { $0.connectionTask = connectionTask }

		try await myInterface.waitForChannelInit()
		logger.info("TesseraClient connected to \(configuration.serverIP):\(configuration.serverPort)")

		self.startConsumerTask(fifo: fifo)
		isConnected = true
	}

	/// Tears down the WireGuard tunnel and stops consuming inbound data.
	public func disconnect() async {
		let snapshot = state.withLock { state in
			let s = (state.interface, state.connectionTask, state.consumerTask)
			state.interface = nil
			state.connectionTask = nil
			state.consumerTask = nil
			state.peerFIFO = nil
			return s
		}
		snapshot.2?.cancel()
		snapshot.1?.cancel()
		if let interface = snapshot.0 {
			try? await interface.close()
		}
		isConnected = false
		logger.info("TesseraClient disconnected")
	}

	/// RAW-encodes `data` and writes it to the server over the tunnel.
	///
	/// - Throws: `TesseraClientError.notConnected` if the tunnel is not established,
	///   or `TesseraClientError.writeFailed` if the underlying write fails.
	public func write(_ data: any RAW_encodable) async throws {
		_ = try await currentChannel()
		var dataCount = 0
		data.RAW_encode(count: &dataCount)
		var buffer = ByteBufferAllocator().buffer(capacity: dataCount)
		buffer.withUnsafeMutableWritableBytes { ptr in
			guard let base = ptr.baseAddress else { return }
			_ = data.RAW_encode(dest: base.assumingMemoryBound(to: UInt8.self))
		}
		buffer.moveWriterIndex(forwardBy: dataCount)
		do {
			// Use the async instance write (future.get()) — the static
			// channel write does EventLoopFuture.wait(), which synchronously
			// blocks a cooperative thread. Blocked cooperative threads starve
			// the Swift concurrency pool: Task.sleep timers never get a thread
			// to run on, so any caller-level timeout deadlocks. The async path
			// suspends instead, keeping the pool free (First Law).
			guard let interface = state.withLock({ $0.interface }) else {
				throw TesseraClientError.notConnected
			}
			try await interface.write(publicKey: configuration.serverPublicKey, data: [UInt8](buffer.readableBytesView))
		} catch {
			throw TesseraClientError.writeFailed(error)
		}
	}

	private func currentChannel() async throws -> Channel {
		guard let interface = state.withLock({ $0.interface }) else {
			throw TesseraClientError.notConnected
		}
		do {
			return try await interface.getChannel()
		} catch {
			throw TesseraClientError.notConnected
		}
	}

	/// Drains the peer FIFO, forwarding each inbound plaintext datagram to `onReceive`.
	private func startConsumerTask(fifo: FIFO<ByteBuffer, Swift.Error>) {
		let consumerTask = Task { [weak self] in
			guard let self else { return }
			let iterator = fifo.makeAsyncConsumer()
			while !Task.isCancelled {
				do {
					guard let data = try await iterator.next(whenTaskCancelled: .finish) else { break }
					data.withUnsafeReadableBytes { ptr in
						self.onReceive?(ptr)
					}
				} catch {
					self.logger.debug("TesseraClient inbound FIFO closed: \(error)")
					break
				}
			}
		}
		state.withLock { $0.consumerTask = consumerTask }
	}
}

/// A tiny mutex-protected box for state that outlives a single lock scope.
private final class LockedState<Value: Sendable>: @unchecked Sendable {
	private var value: Value
	private let lock = NSLock()

	init(_ value: Value) {
		self.value = value
	}

	func withLock<T>(_ body: (inout Value) throws -> T) rethrows -> T {
		lock.lock()
		defer { lock.unlock() }
		return try body(&value)
	}
}
