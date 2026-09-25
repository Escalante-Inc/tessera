import Foundation
import Logging
import NIO
import RAW
import RAW_dh25519
import bedrock_fifo
import QuickLMDB
import wireguard_userspace_nio
import nostr_kit_swift
import tessera_core
import concord

/// The 4-byte magic that prefixes every tessera sync frame ("NEGT").
/// Used to sniff sync traffic out of the shared WireGuard stream.
/// The concord wire codec emits this exact magic, so routing is unchanged.
let negentropyMagicBytes: [UInt8] = Array("NEGT".utf8)

/// Returns true when the given inbound WireGuard data is a sync frame.
func isNegentropyFrame(_ data: ByteBuffer) -> Bool {
	guard data.readableBytes >= negentropyMagicBytes.count else { return false }
	return data.getBytes(at: data.readerIndex, length: negentropyMagicBytes.count) == negentropyMagicBytes
}

/// Serializes tessera sync sessions so that only one reconciliation round
/// holds an LMDB writer transaction (and blocks other writers) at a time.
/// Concord rounds open a read-write transaction on the shared environment for
/// the duration of a round, and LMDB permits a single writer.
actor SyncGate {
	private var isBusy = false

	func run<R: Sendable>(_ work: @Sendable () async throws -> R) async throws -> R {
		while isBusy {
			try await Task.sleep(for: .milliseconds(50))
		}
		isBusy = true
		defer { isBusy = false }
		return try await work()
	}
}

/// Drives concord synchronization with a single peer tessera.
///
/// The role of each side is determined deterministically by comparing WireGuard
/// public keys: the peer with the lexicographically greater public key takes the
/// *initiator* (reconcile) role; the other takes the *responder* role. Because
/// the comparison is anti-symmetric, exactly one side ever initiates — the
/// "both initiate at once" failure mode cannot occur through this code path.
///
/// Inbound sync frames are routed by the per-peer NOSTR task into `syncFIFO`;
/// this manager consumes them and writes replies straight out the shared
/// channel. Concord needs no database-signature handshake: the initiator simply
/// sends its first `.reconcile`, and the responder starts receiving.
struct NegentropySyncManager {
	let tesseraDB: TesseraDB
	let channel: Channel
	let myPublicKey: PublicKey
	let peer: TesseraPeer
	let syncFIFO: FIFO<ByteBuffer, Swift.Error>
	let logLevel: Logger.Level
	let interval: TimeInterval

	/// True when this side plays the initiator role for this peer link.
	var isInitiator: Bool {
		return myPublicKey > peer.publicKey
	}

	/// Empties any stale frames left over from a previous (interrupted) round so a
	/// fresh round starts on a clean FIFO. The non-blocking consumer returns nil
	/// the moment the FIFO is drained.
	private func drainStaleFrames() {
		let consumer = syncFIFO.makeSyncConsumerNonBlocking()
		while (try? consumer.next()) != nil {}
	}

	/// Runs one concord reconciliation round and then reindexes the local database.
	func runOneRound() async throws {
		var logger = Logger(label: "tessera-concord-sync")
		logger.logLevel = logLevel

		drainStaleFrames()

		let transport = ConcordWGTransport<NOSTR_id, TesseraSignedEvent>(
			channel: channel,
			peerPublicKey: peer.publicKey,
			syncFIFO: syncFIFO
		)

		let role: ConcordRole = isInitiator ? .initiator : .responder
		// `oneWaySync: false` — converge both ways (matches the previous
		// negentropy behavior).
		try await runConcordRoundAsync(env: tesseraDB.syncEnvironment, role: role, oneWaySync: false, transport: transport)

		// Events written by concord bypass scribeNewEvent, so rebuild the query
		// indexes (validating signatures) once the round completes. The verified
		// index in the driver already rejects invalid values at store time; this
		// reindex also self-heals any previously-synced poison and repopulates
		// the indexes after the round's raw writes.
		try tesseraDB.reindexAfterSync(logLevel: logLevel)
	}

	/// Loops forever, running a sync round immediately and then every `interval` seconds.
	func runForever(gate: SyncGate) async throws {
		var logger = Logger(label: "tessera-concord-loop")
		logger.logLevel = logLevel

		while !Task.isCancelled {
			do {
				try await gate.run {
					try await runOneRound()
				}
			} catch {
				logger.error("Concord sync round failed", metadata: ["peer": "\(String(describing: peer.publicKey))", "error": "\(String(describing: error))"])
			}
			try await Task.sleep(for: .seconds(interval))
		}
	}
}
