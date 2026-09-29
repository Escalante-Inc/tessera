import Logging
import Foundation
import NIO
import RAW
import RAW_base64
import RAW_dh25519
import bedrock
import QuickLMDB
import nostr_kit_swift

public typealias TesseraSignedEvent = NOSTR_event_signed<UnsignedEvent<ByteBuffer>>

/// A database for storing Tessera `NOSTR_event_signed` and other relavent information.
///
/// The environment and its table catalog are assembled by the QuickLMDB macro
/// layer: `@MDB_environment` generates `open(at:mapHeadroom:fileName:)`, which
/// creates the base directory, sizes the memory map (current file size +
/// headroom), opens the environment (`.noTLS` is always forced), and opens all
/// eight tables in a single setup write-transaction.
///
/// `file:` is omitted so the environment name is a runtime parameter
/// (`fileName:`), matching the original per-tenant on-disk layout at
/// `<base>/<environment>.mdb` with `.noSubDir`.
@MDB_environment(flags: [.noSubDir], maxReaders: 64, maxDBs: 8, mode: [.ownerReadWriteExecute, .groupReadExecute, .otherReadExecute])
public struct TesseraDB: Sendable {
	/// The raw environment handle. Used directly by the concord sync driver
	/// (which opens its own transaction on a dedicated round thread) and by the
	/// typed-transaction operations in `Sources/tessera-core/Database/`.
	public let env: Environment

	/// The logger for this environment instance (`@MDB_state` — configuration
	/// carried on the instance and threaded through the generated `open`).
	@MDB_state
	internal let log: Logger

	/// Primary Database that maps a `UnsignedEvent` `NOSTR_id` to a `NOSTR_event_signed`.
	/// Stores ALL allocated events on the tessera.
	@MDB_table(name: "SignedEvents")
	internal let signedEvents: Database.Strict<NOSTR_id, TesseraSignedEvent>

	// Indexes
	@MDB_table(name: "AuthorIndex")
	internal let authorIndex: Database.DupSort<PublicKey, NOSTR_id>
	@MDB_table(name: "ApplicationIndex")
	internal let applicationIndex: Database.DupSort<NOSTR_application, NOSTR_id>
	@MDB_table(name: "KindIndex")
	internal let kindIndex: Database.DupSort<NOSTR_kind, NOSTR_id>
	@MDB_table(name: "DateIndex")
	internal let dateIndex: Database.DupSort<NOSTR_date, NOSTR_id>
	@MDB_table(name: "TagIndex")
	internal let tagIndex: Database.DupSort<EventTag, NOSTR_id>
	@MDB_table(name: "UserIndex")
	internal let userIndex: Database.Strict<PublicKey, NOSTR_id>

	@MDB_table(name: "ReplaceableEvents")
	internal let replaceableEvents: Database.DupSort<ReplaceableKey, DatedID>

	/// The raw environment handle, used by the concord sync driver (which opens
	/// its own transaction on a dedicated round thread).
	public var syncEnvironment: Environment {
		return env
	}

	/// Deletes the environments files. Equivalent to a `rm -r 'env_file_path'`.
	/// If the environment (or lock) file does not exist, this is a no-op — it does
	/// not throw and does not log an error.
	public static func deleteEnvironment(base: Path, environment: String, logLevel: Logger.Level) throws {
		let finalMdbPath = base.appendingPathComponent("\(environment).mdb")
		let finalLockPath = base.appendingPathComponent("\(environment).mdb-lock")
		var makeLogger = Logger(label: "\(String(describing: Self.self))")
		makeLogger.logLevel = logLevel
		if FileManager.default.fileExists(atPath: finalMdbPath.path()) {
			do {
				makeLogger.debug("deleting tessera database", metadata: ["path": "\(finalMdbPath.path())"])
				try FileManager.default.removeItem(atPath: finalMdbPath.path())
				makeLogger.info(Logger.Message.orange("successfully deleted \(environment) database"))
			} catch {
				makeLogger.error("Error: \(finalMdbPath.path()) couldn’t be removed.")
			}
		}
		if FileManager.default.fileExists(atPath: finalLockPath.path()) {
			do {
				makeLogger.debug("deleting tessera database lock", metadata: ["path": "\(finalLockPath.path())"])
				try FileManager.default.removeItem(atPath: finalLockPath.path())
				makeLogger.info(Logger.Message.orange("successfully deleted \(environment) database lock"))
			} catch {
				makeLogger.error("Error: \(finalLockPath.path()) couldn’t be removed.")
			}
		}
	}
}

extension TesseraDB {
	/// Opens (creating if needed) a tessera environment, preserving the original
	/// `TesseraDB(base:memoryMapSize:logLevel:environment:)` call contract on top
	/// of the macro-generated `open(at:mapHeadroom:fileName:)`:
	///
	/// - `mapHeadroom` is set to `memoryMapSize` so a fresh database gets exactly
	///   the requested map size (`0 + memoryMapSize`), while an existing database
	///   gets `fileSize + memoryMapSize` (never smaller than the old behavior —
	///   LMDB map sizes only grow).
	/// - `fileName` is `"<environment>.mdb"`, matching `deleteEnvironment(base:environment:)`
	///   and the original `<base>/<environment>.mdb` layout.
	public static func openTessera(base: Path, memoryMapSize: size_t, logLevel: Logger.Level, environment: String = "tessera") throws -> TesseraDB {
		let finalPath = base.appendingPathComponent("\(environment).mdb")
		var log = Logger(label: "\(String(describing: Self.self))")
		log.logLevel = logLevel
		log.debug("initializing tessera environment", metadata: ["path": "\(finalPath.path())", "memoryMapSize": "\(memoryMapSize)b"])
		let db = try Self.open(at: base.path(), mapHeadroom: UInt64(memoryMapSize), fileName: "\(environment).mdb", log: log)
		log.trace("opened tessera environment", metadata: ["path": "\(finalPath.path())", "memoryMapSize": "\(memoryMapSize)b"])
		return db
	}
}
