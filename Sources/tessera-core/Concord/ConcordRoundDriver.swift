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
	/// key/id equality check. The round aborts and the transaction rolls back.
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
/// round's write transaction is rolled back wholesale, so a violation leaves
/// the store exactly as it was.
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
		let isValid = rawBytes.withUnsafeBytes { raw -> Bool in
			guard let event = TesseraSignedEvent(RAW_decode: raw) else {
				return false
			}
			return event.isValidSignature() && event.unsignedEvent.id == key
		}
		guard isValid else {
			throw ConcordSyncError.invalidValue(key)
		}
		try inner.storeBytes(key, ConcordOwnedBytes(rawBytes))
	}
}

/// Runs one concord round synchronously on the CALLING thread.
///
/// Opens a write transaction, attaches the verified LMDB index over the
/// `SignedEvents` database, runs the engine, and releases the index and cursor
/// before committing. On any error the transaction is aborted and the store is
/// left untouched.
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
	let tx = try Transaction<Write>(env: env)
	do {
		do {
			let db = try Database(env: env, name: databaseName, flags: [], tx: tx)
			let cursor = try Cursor(db: db, tx: tx)
			let index = VerifiedConcordIndex(ConcordLMDBIndex<NOSTR_id, TesseraSignedEvent>(database: db, cursor: cursor))
			let session = ConcordSession(index: index, transport: transport, role: role, oneWaySync: oneWaySync)
			try session.runRound()
		} catch {
			// db/cursor/index are released here, before the transaction closes.
			tx.abort()
			throw error
		}
		// db/cursor/index released before the commit.
		try tx.commit()
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
