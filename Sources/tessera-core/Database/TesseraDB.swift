import Logging
import Foundation
import NIO
import RAW
import RAW_base64
import RAW_dh25519
import bedrock
import QuickLMDB
import nostr_kit_swift

/// A database for storing Tessera `NOSTR_event_signed` and other relavent information.
public struct TesseraDB:Sendable {
	internal let log:Logger
	internal let env:Environment
	
	/// Primary Database that maps a `UnsignedEvent` `NOSTR_id` to a `NOSTR_event_signed`.
	/// Stores ALL allocated events on the tessera.
	internal let signedEvents:Database.Strict<NOSTR_id, StoredSignedEvent>
	
	/// Deletes the environments files. Equivalent to a `rm -r 'env_file_path'`.
	public static func deleteEnvironment(base:Path, environment:String, logLevel:Logger.Level) throws {
		let finalMdbPath = base.appendingPathComponent("\(environment).mdb")
		let finalLockPath = base.appendingPathComponent("\(environment).mdb-lock")
		var makeLogger = Logger(label:"\(String(describing:Self.self))")
		makeLogger.logLevel = logLevel
		do {
			makeLogger.debug("deleting tessera database", metadata:["path":"\(finalMdbPath.path())"])
			try FileManager.default.removeItem(atPath:finalMdbPath.path())
			makeLogger.info(Logger.Message.orange("successfully deleted \(environment) database"))
		} catch {
			makeLogger.error("Error: \(finalMdbPath.path()) couldn’t be removed or doesn't exist.")
		}
		do {
			makeLogger.debug("deleting tessera database lock", metadata:["path":"\(finalLockPath.path())"])
			try FileManager.default.removeItem(atPath:finalLockPath.path())
			makeLogger.info(Logger.Message.orange("successfully deleted \(environment) database lock"))
		} catch {
			makeLogger.error("Error: \(finalLockPath.path()) couldn’t be removed or doesn't exist.")
		}
	}
	
	public init(base:Path, memoryMapSize:size_t, logLevel:Logger.Level) throws {
		let finalPath = base.appendingPathComponent("tessera.mdb")
		var log = Logger(label:"\(String(describing:Self.self))")
		log.logLevel = logLevel
		self.log = log
		log.debug("initializing tessera environment", metadata:["path":"\(finalPath.path())", "memoryMapSize":"\(memoryMapSize)b"])
		env = try Environment(path:finalPath.path(), flags:[.noSubDir], mapSize:memoryMapSize, maxReaders:64, maxDBs:3, mode:[.ownerReadWriteExecute, .groupReadExecute, .otherReadExecute])
		log.trace("created tessera environment. now creating initial transaction", metadata:["path":"\(finalPath.path())", "memoryMapSize":"\(memoryMapSize)b"])
		let newTrans = try Transaction(env:env, readOnly:false)
		log.trace("created initial transaction. now creating events database", metadata:["path":"\(finalPath.path())", "memoryMapSize":"\(memoryMapSize)b"])
		signedEvents = try Database.Strict<NOSTR_id, StoredSignedEvent>(env:env, name:"SignedEvents", flags:[.create], tx:newTrans)
		log.trace("created signed events database. now committing transaction", metadata:["path":"\(finalPath.path())", "memoryMapSize":"\(memoryMapSize)b"])
		try newTrans.commit()
	}
}
