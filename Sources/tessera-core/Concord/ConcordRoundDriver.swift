import Foundation
import NIO
import Logging
import RAW
import QuickLMDB
import nostr_kit_swift
import concord

/// The canonical name of the primary strict database that tessera reconciles.
public let tesseraSyncDatabaseName = "SignedEvents"

/// Errors raised by the tessera concord driver (beyond the engine's own
/// `ConcordError`).
public enum ConcordSyncError: Swift.Error, Equatable {
	/// Incoming value bytes failed event decode, signature validation, or the
	/// key/id equality check. The round aborts and nothing is written to the
	/// store.
	case invalidValue(NOSTR_id)
}

/// `ConcordIndex` wrapper that verifies every incoming event before it is
/// written to the store.
///
/// Concord stores value bytes verbatim and never decodes them; a hostile (or
/// buggy) peer could therefore push well-framed but semantically invalid
/// bytes. This wrapper decodes the incoming bytes into a `TesseraSignedEvent`
/// and rejects it — aborting the round — when the signature is invalid or the
/// event's id does not match the key. Nothing invalid is ever stored, and the
/// round is rolled back wholesale, so a violation leaves the store exactly as
/// it was.
///
/// All remaining index operations delegate to the wrapped LMDB driver.
public struct VerifiedConcordIndex: ConcordIndex {
	public typealias Key = NOSTR_id
	public typealias Value = TesseraSignedEvent

	let inner: ConcordLMDBIndex<NOSTR_id, TesseraSignedEvent>

	public init(_ inner: ConcordLMDBIndex<NOSTR_id, TesseraSignedEvent>) {
		self.inner = inner
	}

	public func entryCount() throws -> Int {
		return try inner.entryCount()
	}

	public func firstKey() throws -> NOSTR_id? {
		return try inner.firstKey()
	}

	public func keyCount(in lower: NOSTR_id?, _ upper: NOSTR_id?) throws -> Int {
		return try inner.keyCount(in: lower, upper)
	}

	public func fingerprint(of lower: NOSTR_id?, _ upper: NOSTR_id?) throws -> Fingerprint {
		return try inner.fingerprint(of: lower, upper)
	}

	public func fingerprintAndAdvance(begin: NOSTR_id?, count: Int, end: NOSTR_id?) throws -> (boundary: NOSTR_id?, fingerprint: Fingerprint) {
		return try inner.fingerprintAndAdvance(begin: begin, count: count, end: end)
	}

	public func forEachKey(in lower: NOSTR_id?, _ upper: NOSTR_id?, _ body: (NOSTR_id) throws -> Void) throws {
		try inner.forEachKey(in: lower, upper, body)
	}

	public func loadBytes(_ key: NOSTR_id) throws -> (any ConcordByteView)? {
		return try inner.loadBytes(key)
	}

	public func storeBytes(_ key: NOSTR_id, _ content: consuming any ConcordByteView) throws {
		// The `consuming` parameter has exactly one legally-permitted use, so
		// detach it into owned storage first (the one sanctioned copy), then
		// verify and delegate with a fresh owned view.
		let rawBytes: [UInt8] = content.withUnsafeBytes { Array($0) }
		guard isValidSignedEvent(key, rawBytes) else {
			throw ConcordSyncError.invalidValue(key)
		}
		try inner.storeBytes(key, ConcordOwnedBytes(rawBytes))
	}
}

/// Whether `rawBytes` is a validly-encoded `TesseraSignedEvent` whose signature
/// is valid and whose own id matches `key`.
private func isValidSignedEvent(_ key: NOSTR_id, _ rawBytes: [UInt8]) -> Bool {
	return rawBytes.withUnsafeBytes { raw -> Bool in
		guard let event = TesseraSignedEvent(RAW_decode: raw) else {
			return false
		}
		return event.isValidSignature() && event.unsignedEvent.id == key
	}
}

/// A `ConcordIndex` that runs the round's reads against the live store but
/// BUFFERS every `storeBytes` write in memory instead of writing immediately.
///
/// This is the key to the read-then-flush model: the whole network exchange
/// proceeds on a READ transaction (which never blocks the LMDB writer), while
/// incoming events are validated and held here. The caller drains the buffer
/// (`takePending`) after the round and flushes it under a single short WRITE
/// transaction, so the writer lock is never held across peer I/O.
///
/// Validation still happens at buffer time, so an invalid frame from the peer
/// aborts the round with `ConcordSyncError.invalidValue` before anything is
/// written — exactly as the verified index does.
final class BufferedConcordIndex: ConcordIndex {
	typealias Key = NOSTR_id
	typealias Value = TesseraSignedEvent

	let reader: ConcordLMDBIndex<NOSTR_id, TesseraSignedEvent>
	private var pending: [(key: NOSTR_id, bytes: [UInt8])] = []

	init(_ reader: ConcordLMDBIndex<NOSTR_id, TesseraSignedEvent>) {
		self.reader = reader
	}

	func entryCount() throws -> Int {
		return try reader.entryCount()
	}

	func firstKey() throws -> NOSTR_id? {
		return try reader.firstKey()
	}

	func keyCount(in lower: NOSTR_id?, _ upper: NOSTR_id?) throws -> Int {
		return try reader.keyCount(in: lower, upper)
	}

	func fingerprint(of lower: NOSTR_id?, _ upper: NOSTR_id?) throws -> Fingerprint {
		return try reader.fingerprint(of: lower, upper)
	}

	func fingerprintAndAdvance(begin: NOSTR_id?, count: Int, end: NOSTR_id?) throws -> (boundary: NOSTR_id?, fingerprint: Fingerprint) {
		return try reader.fingerprintAndAdvance(begin: begin, count: count, end: end)
	}

	func forEachKey(in lower: NOSTR_id?, _ upper: NOSTR_id?, _ body: (NOSTR_id) throws -> Void) throws {
		try reader.forEachKey(in: lower, upper, body)
	}

	func loadBytes(_ key: NOSTR_id) throws -> (any ConcordByteView)? {
		return try reader.loadBytes(key)
	}

	func storeBytes(_ key: NOSTR_id, _ content: consuming any ConcordByteView) throws {
		let rawBytes: [UInt8] = content.withUnsafeBytes { Array($0) }
		guard isValidSignedEvent(key, rawBytes) else {
			throw ConcordSyncError.invalidValue(key)
		}
		pending.append((key, rawBytes))
	}

	/// Drains the buffered writes for the caller to flush under a write
	/// transaction. Clears the internal buffer.
	func takePending() -> [(key: NOSTR_id, bytes: [UInt8])] {
		defer { pending.removeAll(keepingCapacity: true) }
		return pending
	}
}

/// Thread-safe lazily-constructed holder of the raw `Database` handle for each
/// sync environment.
///
/// The `Database` initializer needs a write transaction solely to run
/// `mdb_dbi_open`; because `SignedEvents` is already open at `TesseraDB` setup
/// this merely returns the cached handle and the base handle lives in the
/// environment. Building it once here means no write transaction is ever
/// opened to service a round — the only write transaction in the sync path is
/// the final flush. The strong `Environment` reference keeps the entry's
/// identity stable so address reuse can never yield a stale handle.
final class ConcordDatabaseHandle: @unchecked Sendable {
	static let shared = ConcordDatabaseHandle()
	private let lock = NSLock()
	private var cache: [ObjectIdentifier: (env: Environment, db: Database)] = [:]

	func handle(for env: Environment, databaseName: String) throws -> Database {
		let key = ObjectIdentifier(env)
		lock.lock()
		defer { lock.unlock() }
		if let entry = cache[key], entry.env === env {
			return entry.db
		}
		let setup = try Transaction<Write>(env: env)
		let db = try Database(env: env, name: databaseName, flags: [], tx: setup)
		// Commit (not abort) so a not-yet-open sub-db handle registration
		// persists; the commit is a no-op when the handle is already cached.
		// This transaction performs no network I/O and is closed before any
		// round runs, so it can never be held across the peer exchange.
		try setup.commit()
		cache[key] = (env, db)
		return db
	}
}

/// Runs one concord round synchronously on the CALLING thread.
///
/// The round is split into two phases so the LMDB writer lock is never held
/// across the network exchange:
///
/// 1. A READ transaction hosts the entire round (reconcile, id-list exchange,
///    and data transfer). Reads never block the single LMDB writer, so a peer
///    that stalls, goes offline, or disappears cannot wedge the writer. Incoming
///    events are validated and buffered in memory (not written) by the
///    `BufferedConcordIndex`.
/// 2. After the round converges, the buffered events are flushed under ONE
///    short WRITE transaction. No network I/O happens here, so the writer lock
///    is held only for the duration of the batch and can never be left held.
///
/// If the round throws (e.g. transport failure or an invalid frame), the read
/// transaction is aborted and nothing is written.
///
/// LMDB transactions are thread-confined, so callers must invoke this on the
/// thread that will own the transaction — use `runConcordRoundAsync` for a
/// self-managed dedicated thread.
public func runConcordRoundSync<Transport: ConcordTransport>(
	env: Environment,
	databaseName: String = tesseraSyncDatabaseName,
	role: ConcordRole,
	oneWaySync: Bool = false,
	transport: Transport
) throws where Transport.Key == NOSTR_id, Transport.Value == TesseraSignedEvent {
	// Obtain (caching after first use) the raw Database handle for the sync DB.
	let db = try ConcordDatabaseHandle.shared.handle(for: env, databaseName: databaseName)

	// Phase 1 — the whole network round runs on a READ transaction. Reads never
	// block the LMDB writer (many readers, one writer), so even a stalled peer
	// holds no writer lock here. Incoming events are validated and buffered.
	var pending: [(key: NOSTR_id, bytes: [UInt8])] = []
	do {
		let readTx = try Transaction<Read>(env: env)
		do {
			let cursor = try Cursor(db: db, tx: readTx)
			let index = BufferedConcordIndex(ConcordLMDBIndex<NOSTR_id, TesseraSignedEvent>(database: db, cursor: cursor))
			let session = ConcordSession(index: index, transport: transport, role: role, oneWaySync: oneWaySync)
			try session.runRound()
			pending = index.takePending()
		} catch {
			// cursor + index are released here, before the read transaction
			// closes. Nothing was written, so abort is a no-op cleanup.
			readTx.abort()
			throw error
		}
		// cursor + index released before the read transaction closes.
		readTx.abort()
	}

	// Phase 2 — flush the buffered events in one short WRITE transaction. No
	// network I/O runs here, so the writer lock is held only for the batch and
	// can never be left held by a stalled peer.
	guard !pending.isEmpty else { return }
	let writeTx = try Transaction<Write>(env: env)
	do {
		do {
			let cursor = try Cursor(db: db, tx: writeTx)
			let writer = ConcordLMDBIndex<NOSTR_id, TesseraSignedEvent>(database: db, cursor: cursor)
			for entry in pending {
				try writer.storeBytes(entry.key, ConcordOwnedBytes(entry.bytes))
			}
		} catch {
			// writer + cursor are released here, before the transaction closes.
			writeTx.abort()
			throw error
		}
		// writer + cursor released before the commit.
		try writeTx.commit()
	}
}

/// Runs one concord round on a dedicated thread and awaits its completion.
///
/// The engine and its LMDB transaction are blocking and thread-confined; this
/// helper owns the thread lifecycle so async callers (the sync manager and the
/// end-to-end tests) never block the cooperative pool.
public func runConcordRoundAsync<Transport: ConcordTransport>(
	env: Environment,
	databaseName: String = tesseraSyncDatabaseName,
	role: ConcordRole,
	oneWaySync: Bool = false,
	transport: Transport
) async throws where Transport.Key == NOSTR_id, Transport.Value == TesseraSignedEvent {
	try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Swift.Error>) in
		Thread.detachNewThread {
			do {
				try runConcordRoundSync(env: env, databaseName: databaseName, role: role, oneWaySync: oneWaySync, transport: transport)
				cont.resume()
			} catch {
				cont.resume(throwing: error)
			}
		}
	}
}
