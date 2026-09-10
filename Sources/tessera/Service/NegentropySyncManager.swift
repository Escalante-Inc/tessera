import Foundation
import Logging
import NIO
import RAW
import RAW_dh25519
import bedrock_pthread
import bedrock_fifo
import QuickLMDB
import negentropy_swift
import wireguard_userspace_nio
import tessera_core

/// The 4-byte magic that prefixes every negentropy frame ("NEGT").
/// Used to sniff sync traffic out of the shared WireGuard stream.
let negentropyMagicBytes: [UInt8] = Array("NEGT".utf8)

/// Returns true when the given inbound WireGuard data is a negentropy frame.
func isNegentropyFrame(_ data: ByteBuffer) -> Bool {
	guard data.readableBytes >= negentropyMagicBytes.count else { return false }
	return data.getBytes(at: data.readerIndex, length: negentropyMagicBytes.count) == negentropyMagicBytes
}

/// Serializes negentropy sync sessions so that only one reconciliation round
/// holds an LMDB writer transaction (and blocks other writers) at a time.
/// The negentropy threads each open a read-write transaction on the shared
/// environment for the duration of a round, and LMDB permits a single writer.
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

/// Drives negentropy synchronization with a single peer tessera.
///
/// The role of each side is determined deterministically by comparing WireGuard
/// public keys: the peer with the lexicographically greater public key takes the
/// *initiator* (sync thread) role; the other takes the *responder* (listen thread)
/// role. Because the comparison is anti-symmetric, exactly one side ever initiates
/// — the "both initiate at once" failure mode cannot occur through this code path.
///
/// Inbound negentropy frames are routed by the per-peer NOSTR task into `syncFIFO`;
/// this manager consumes them and writes replies straight out the shared channel.
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
		var consumer = syncFIFO.makeSyncConsumerNonBlocking()
		while (try? consumer.next()) != nil {}
	}

	/// Waits (cancellably) for the first inbound frame on the sync FIFO.
	/// Returns nil if the enclosing task is cancelled before any frame arrives.
	private func awaitFirstFrame(logger: Logger) async throws -> ByteBuffer? {
		var consumer = syncFIFO.makeSyncConsumerNonBlocking()
		while !Task.isCancelled {
			if let frame = try? consumer.next() {
				return frame
			}
			try await Task.sleep(for: .milliseconds(100))
		}
		return nil
	}

	/// Runs one reconciliation round and then reindexes the local database.
	func runOneRound() async throws {
		var logger = Logger(label: "tessera-negnetropy-sync")
		logger.logLevel = logLevel

		let strictDBs: [any NegentropyDatabaseStrict] = tesseraDB.syncStrictDBs
		let basicDBs: [any NegentropyDatabase] = []

		drainStaleFrames()

		if isInitiator {
			logger.debug("Acting as negentropy initiator toward peer")
			// `oneWaySync: false` — converge both ways.
			_ = try await NegentropySyncThread.run((basicDBs, strictDBs, channel, syncFIFO, peer.publicKey, false))
		} else {
			logger.debug("Acting as negentropy responder toward peer")
			// The listen thread requires the initiator's first frame (its database
			// signatures) up front. Read it off the sync FIFO, then hand the FIFO
			// over to the listen thread for the remainder of the conversation.
			guard let firstFrame = try await awaitFirstFrame(logger: logger) else {
				logger.debug("Responder round ended before the initiator sent its database signatures")
				return
			}
			_ = try await NegentropyListenThread.run((basicDBs, strictDBs, channel, syncFIFO, peer.publicKey, firstFrame))
		}

		// Events written by negentropy bypass scribeNewEvent, so rebuild the query
		// indexes (validating signatures) once the round completes.
		try tesseraDB.reindexAfterSync(logLevel: logLevel)
	}

	/// Loops forever, running a sync round immediately and then every `interval` seconds.
	func runForever(gate: SyncGate) async throws {
		var logger = Logger(label: "tessera-negentropy-loop")
		logger.logLevel = logLevel

		while !Task.isCancelled {
			do {
				try await gate.run {
					try await runOneRound()
				}
			} catch {
				logger.error("Negentropy sync round failed", metadata: ["peer": "\\(String(describing: peer.publicKey))", "error": "\\(String(describing: error))"])
			}
			try await Task.sleep(for: .seconds(interval))
		}
	}
}
