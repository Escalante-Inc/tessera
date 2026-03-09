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
public struct TesseraDB:Sendable {
	internal let log:Logger
	internal let env:Environment
	
	/// Primary Database that maps a `UnsignedEvent` `NOSTR_id` to a `NOSTR_event_signed`.
	/// Stores ALL allocated events on the tessera.
	internal let signedEvents:Database.Strict<NOSTR_id, TesseraSignedEvent>
	
	// Indexes
	internal let authorIndex:Database.DupSort<PublicKey, NOSTR_id>
	internal let kindIndex:Database.DupSort<NOSTR_kind, NOSTR_id>
	internal let dateIndex:Database.DupSort<NOSTR_date, NOSTR_id>
	internal let tagIndex:Database.DupSort<EventTag, NOSTR_id>
	internal let userIndex:Database.Strict<PublicKey, NOSTR_id>
	
	internal let replaceableEvents:Database.DupSort<ReplaceableKey, DatedID>
	
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
		env = try Environment(path:finalPath.path(), flags:[.noSubDir], mapSize:memoryMapSize, maxReaders:64, maxDBs:7, mode:[.ownerReadWriteExecute, .groupReadExecute, .otherReadExecute])
		log.trace("created tessera environment. now creating initial transaction", metadata:["path":"\(finalPath.path())", "memoryMapSize":"\(memoryMapSize)b"])
		let newTrans = try Transaction(env:env, readOnly:false)
		log.trace("created initial transaction. now creating databases", metadata:["path":"\(finalPath.path())", "memoryMapSize":"\(memoryMapSize)b"])
		signedEvents = try Database.Strict<NOSTR_id, TesseraSignedEvent>(env:env, name:"SignedEvents", flags:[.create], tx:newTrans)
		authorIndex = try Database.DupSort<PublicKey, NOSTR_id>(env:env, name:"AuthorIndex", flags:[.create], tx:newTrans)
		kindIndex = try Database.DupSort<NOSTR_kind, NOSTR_id>(env:env, name:"KindIndex", flags:[.create], tx:newTrans)
		dateIndex = try Database.DupSort<NOSTR_date, NOSTR_id>(env:env, name:"DateIndex", flags:[.create], tx:newTrans)
		tagIndex = try Database.DupSort<EventTag, NOSTR_id>(env:env, name:"TagIndex", flags:[.create], tx:newTrans)
		userIndex = try Database.Strict<PublicKey, NOSTR_id>(env:env, name:"UserIndex", flags:[.create], tx:newTrans)
		replaceableEvents = try Database.DupSort<ReplaceableKey, DatedID>(env:env, name:"ReplaceableEvents", flags:[.create], tx:newTrans)
		log.trace("created all databases. now committing transaction", metadata:["path":"\(finalPath.path())", "memoryMapSize":"\(memoryMapSize)b"])
		try newTrans.commit()
	}
}
