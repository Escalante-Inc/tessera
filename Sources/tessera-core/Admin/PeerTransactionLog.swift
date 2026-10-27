import Foundation
import Logging
import bedrock
import Synchronization

// MARK: - Peer Transaction Records

/// One recorded interaction between the relay and a configured peer.
///
/// Records are appended as one JSON object per line to `peer-transactions.jsonl`
/// inside the database directory. The admin CLI and webui read this file to show
/// recent peer traffic.
public struct PeerTransactionRecord: Codable, Sendable, Equatable {
	/// When the transaction occurred.
	public var timestamp:Foundation.Date
	/// The peer's public key, base64 encoded.
	public var peer:String
	/// `inbound` (the peer sent something to this relay), `outbound` (this relay served/replied to the peer), or `local` (a local maintenance action).
	public var direction:String
	/// The transaction type: `event`, `req`, `notice`, `sync`, or `error`.
	public var type:String
	/// A short human-readable summary of the transaction.
	public var detail:String

	public init(timestamp:Foundation.Date, peer:String, direction:String, type:String, detail:String) {
		self.timestamp = timestamp
		self.peer = peer
		self.direction = direction
		self.type = type
		self.detail = detail
	}
}

// MARK: - Peer Transaction Log

/// A thread-safe, file-backed JSONL log of peer transactions.
///
/// The daemon appends a record on every notable peer interaction (scribed events,
/// served requests, notices, concord sync rounds, rejected messages). The admin
/// interface reads the same file. The log rotates itself when it exceeds `maxBytes`,
/// keeping the most recent `keepOnRotate` records.
public final class PeerTransactionLog: Sendable {

	/// The path of the transactions file inside `base`.
	public static func filePath(base:Path) -> Path {
		return base.appendingPathComponent("peer-transactions.jsonl")
	}

	private let path:String
	private let logLevel:Logger.Level
	private let maxBytes:Int
	private let keepOnRotate:Int
	private let lock = Mutex<Bool>(false)
	private nonisolated(unsafe) var logger:Logger

	/// Creates a log rooted at `base` (the database directory). The file is created
	/// lazily on the first recorded transaction.
	public init(base:Path, logLevel:Logger.Level = .debug, maxBytes:Int = 2 * 1024 * 1024, keepOnRotate:Int = 2000) {
		self.path = PeerTransactionLog.filePath(base: base).path()
		self.logLevel = logLevel
		self.maxBytes = maxBytes
		self.keepOnRotate = keepOnRotate
		var newLogger = Logger(label: "tessera.peer-transactions")
		newLogger.logLevel = logLevel
		self.logger = newLogger
	}

	/// Appends a transaction record. IO errors are logged and swallowed — transaction
	/// logging must never take the relay down.
	public func record(peer:String, direction:String, type:String, detail:String) {
		let record = PeerTransactionRecord(timestamp: Date(), peer: peer, direction: direction, type: type, detail: detail)
		lock.withLock { _ in
			do {
				let fileManager = FileManager.default
				if !fileManager.fileExists(atPath: path) {
					// ensure the parent directory exists (it normally does — the database lives there).
					let parent = (path as NSString).deletingLastPathComponent
					try? fileManager.createDirectory(atPath: parent, withIntermediateDirectories: true)
					if !fileManager.createFile(atPath: path, contents: nil) {
						logger.log(level: .error, "failed to create peer transaction log at '\(path)'")
						return
					}
				}
				guard let handle = FileHandle(forWritingAtPath: path) else {
					logger.log(level: .error, "failed to open peer transaction log at '\(path)'")
					return
				}
				defer { try? handle.close() }
				try handle.seekToEnd()
				var line = try encoder.encode(record)
				line.append(0x0A) // newline
				try handle.write(contentsOf: line)
			} catch {
				logger.log(level: .error, "failed to append peer transaction: \(error)")
				return
			}
			rotateIfNeeded()
		}
	}

	/// Reads the last `limit` records from the log, newest first. Malformed lines are skipped.
	public func read(limit:Int) -> [PeerTransactionRecord] {
		return lock.withLock { _ in
			guard let data = FileManager.default.contents(atPath: path), !data.isEmpty else { return [] }
			let decoder = JSONDecoder()
			decoder.dateDecodingStrategy = .iso8601
			var records:[PeerTransactionRecord] = []
			var start = data.startIndex
			for index in data.indices where data[index] == 0x0A {
				let lineData = data.subdata(in: (start..<index))
				start = data.index(after: index)
				if lineData.isEmpty { continue }
				if let record = try? decoder.decode(PeerTransactionRecord.self, from: lineData) {
					records.append(record)
				} else {
					logger.log(level: .warning, "skipping malformed line in peer transaction log")
				}
			}
			if records.count <= limit { return records.reversed() }
			return Array(records[(records.count - limit)...]).reversed()
		}
	}

	// MARK: - Rotation

	private var encoder:JSONEncoder {
		let encoder = JSONEncoder()
		encoder.dateEncodingStrategy = .iso8601
		encoder.outputFormatting = [.sortedKeys]
		return encoder
	}

	/// Rewrites the file keeping only the most recent `keepOnRotate` records when it
	/// has grown past `maxBytes`. Called with the lock held.
	private func rotateIfNeeded() {
		guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
			let size = attributes[.size] as? Int, size > maxBytes else { return }
		guard let data = FileManager.default.contents(atPath: path), !data.isEmpty else { return }
		let decoder = JSONDecoder()
		decoder.dateDecodingStrategy = .iso8601
		var records:[PeerTransactionRecord] = []
		var start = data.startIndex
		for index in data.indices where data[index] == 0x0A {
			let lineData = data.subdata(in: (start..<index))
			start = data.index(after: index)
			if let record = try? decoder.decode(PeerTransactionRecord.self, from: lineData) {
				records.append(record)
			}
		}
		let kept = records.count <= keepOnRotate ? records : Array(records[(records.count - keepOnRotate)...])
		let newEncoder = JSONEncoder()
		newEncoder.dateEncodingStrategy = .iso8601
		newEncoder.outputFormatting = [.sortedKeys]
		var payload = Data()
		for record in kept {
			var line = (try? newEncoder.encode(record)) ?? Data()
			line.append(0x0A)
			payload.append(line)
		}
		do {
			try payload.write(to: URL(fileURLWithPath: path), options: .atomic)
			logger.log(level: logLevel, "rotated peer transaction log; kept \(kept.count) of \(records.count) records")
		} catch {
			logger.log(level: .error, "failed to rotate peer transaction log: \(error)")
		}
	}
}
