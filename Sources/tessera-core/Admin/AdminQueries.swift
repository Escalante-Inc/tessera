import Foundation
import RAW
import RAW_base64
import RAW_dh25519
import QuickLMDB
import nostr_kit_swift
import Logging

// MARK: - Result Types

/// A registered tessera user, as reported by the admin interface.
public struct AdminUserInfo: Sendable, Codable, Equatable {
	/// The user's public key, base64 encoded.
	public let publicKey:String
	/// The user's display name from their kind-0 profile content (nil if missing or unparsable).
	public let name:String?
	/// The id of the user's kind-0 profile event, base64 encoded.
	public let profileID:String
	/// The date of the user's kind-0 profile event.
	public let profileDate:Foundation.Date?
	/// The access levels the user is permitted to READ, expanded from the 256-bit bit array.
	public let readAccessLevels:[UInt8]
	/// The access levels the user is permitted to WRITE, expanded from the 256-bit bit array.
	public let writeAccessLevels:[UInt8]
	/// The number of events authored by this user currently indexed in the database.
	public let eventCount:Int
	/// The date of the most recent event authored by this user (nil if the user has authored none).
	public let lastActivity:Foundation.Date?

	/// Convenience formatting for a set of access levels: `all`, `none`, or a
	/// (truncated) comma-separated list. Used by both the CLI and the webui.
	public static func format(_ levels:[UInt8]) -> String {
		guard !levels.isEmpty else { return "none" }
		guard levels.count < 256 else { return "all" }
		let joined = levels.map(String.init).joined(separator: ",")
		if joined.count <= 24 { return joined }
		let head = levels.prefix(4).map(String.init).joined(separator: ",")
		return "\(head),… (+\(levels.count - 4))"
	}
}

/// Aggregate statistics over the event database, as reported by the admin interface.
public struct AdminEventStats: Sendable, Codable, Equatable {
	/// Total number of events stored in the primary store.
	public let totalEvents:Int
	/// Total number of registered users (kind-0 profile events indexed in the user index).
	public let userCount:Int
	/// Number of events per kind.
	public let perKind:[Int:Int]
	/// Number of events per application.
	public let perApplication:[Int:Int]
	/// Number of events per author (base64 public key).
	public let perAuthor:[String:Int]
	/// Date of the oldest event in the database.
	public let oldestEvent:Foundation.Date?
	/// Date of the newest event in the database.
	public let newestEvent:Foundation.Date?
	/// Number of events with a creation date within the last 24 hours.
	public let last24h:Int
	/// Number of events with a creation date within the last 7 days.
	public let last7d:Int
	/// Number of kind-5 (deletion) events.
	public let deletionCount:Int
	/// Number of distinct replaceable-event keys (one per replaceable event slot).
	public let replaceableEvents:Int
	/// Total number of replaceable-event revisions indexed.
	public let replaceableRevisions:Int
	/// Number of kind-1 (access level) events.
	public let accessLevelCount:Int
	/// Size of the database file on disk, in bytes (filled in by the caller).
	public let databaseFileSize:Int64

	public init(totalEvents:Int, userCount:Int, perKind:[Int:Int], perApplication:[Int:Int], perAuthor:[String:Int], oldestEvent:Foundation.Date?, newestEvent:Foundation.Date?, last24h:Int, last7d:Int, deletionCount:Int, replaceableEvents:Int, replaceableRevisions:Int, accessLevelCount:Int, databaseFileSize:Int64) {
		self.totalEvents = totalEvents
		self.userCount = userCount
		self.perKind = perKind
		self.perApplication = perApplication
		self.perAuthor = perAuthor
		self.oldestEvent = oldestEvent
		self.newestEvent = newestEvent
		self.last24h = last24h
		self.last7d = last7d
		self.deletionCount = deletionCount
		self.replaceableEvents = replaceableEvents
		self.replaceableRevisions = replaceableRevisions
		self.accessLevelCount = accessLevelCount
		self.databaseFileSize = databaseFileSize
	}
	/// Returns a copy of these stats with the database file size filled in
	/// (the query layer itself does not know the on-disk size).
	public func withDatabaseFileSize(_ size:Int64) -> AdminEventStats {
		return AdminEventStats(
			totalEvents: totalEvents, userCount: userCount, perKind: perKind,
			perApplication: perApplication, perAuthor: perAuthor, oldestEvent: oldestEvent,
			newestEvent: newestEvent, last24h: last24h, last7d: last7d,
			deletionCount: deletionCount, replaceableEvents: replaceableEvents,
			replaceableRevisions: replaceableRevisions, accessLevelCount: accessLevelCount,
			databaseFileSize: size
		)
	}
}

/// A kind-1 (access level) event, as reported by the admin interface.
public struct AdminAccessLevelInfo: Sendable, Codable, Equatable {
	/// The access level index.
	public let level:UInt8
	/// The access level name (from the `permName` tag).
	public let name:String
	/// The creation date of the access-level event.
	public let date:Foundation.Date
	/// The author of the access-level event, base64 encoded.
	public let author:String
	/// The id of the access-level event, base64 encoded.
	public let eventID:String
}

// MARK: - Query Implementations

extension TesseraDB {

	/// Lists every registered user with their access levels and activity information.
	///
	/// Activity is derived from the author index: the number of events authored by the
	/// user, and the date of the most recent one. `lastActivity` is `nil` for users that
	/// have a profile but no indexed events.
	@MDB_transact(.readOnly)
	public func adminListUsers() throws -> [AdminUserInfo] {
		// Pass 1: collect (user, profile event id) pairs from the user index.
		var profiles:[(user:PublicKey, profileID:NOSTR_id)] = []
		try #cursor(TesseraDB.self, database: \.userIndex) { cursor in
			var iterator:(key:PublicKey, value:NOSTR_id)? = try? cursor.opFirst(returning: (key: PublicKey, value: NOSTR_id).self)
			while let entry = iterator {
				profiles.append((user:entry.key, profileID:entry.value))
				guard let next = try? cursor.opNext(returning: (key: PublicKey, value: NOSTR_id).self) else { break }
				iterator = next
			}
		}

		// Pass 2: collect (author, event id) pairs from the author index.
		var authored:[(author:PublicKey, eventID:NOSTR_id)] = []
		try #cursor(TesseraDB.self, database: \.authorIndex) { cursor in
			var iterator:(key:PublicKey, value:NOSTR_id)? = try? cursor.opFirst(returning: (key: PublicKey, value: NOSTR_id).self)
			while let entry = iterator {
				authored.append((author:entry.key, eventID:entry.value))
				if let nextDup = try? cursor.opNextDup() {
					iterator = (key:entry.key, value:nextDup)
				} else {
					// exhausted this author's dups; advance to the next author.
					iterator = try? cursor.opNextNoDup(returning: (key: PublicKey, value: NOSTR_id).self)
				}
			}
		}

		// Pass 3: load the collected events from the primary store and derive details.
		var details:[String:(name:String?, profileDate:Foundation.Date?, read:[UInt8], write:[UInt8])] = [:]
		var activity:[String:(count:Int, last:Foundation.Date?)] = [:]
		try #cursor(TesseraDB.self, database: \.signedEvents) { cursor in
			for entry in profiles {
				guard try cursor.containsEntry(key: entry.profileID) else { continue }
				let profileEvent = try cursor.opSet(key: entry.profileID)
				let parsed = AdminQueriesSupport.parseProfileEvent(profileEvent)
				details[String(RAW_base64.encode(entry.user))] = (name:parsed.name, profileDate:profileEvent.unsignedEvent.date.currentDate(), read:parsed.read, write:parsed.write)
			}
			for entry in authored {
				let authorKey = String(RAW_base64.encode(entry.author))
				var entry_activity = activity[authorKey] ?? (count:0, last:nil)
				entry_activity.count += 1
				if try cursor.containsEntry(key: entry.eventID) {
					let event = try cursor.opSet(key: entry.eventID)
					let date = event.unsignedEvent.date.currentDate()
					if entry_activity.last == nil || date > entry_activity.last! {
						entry_activity.last = date
					}
				}
				activity[authorKey] = entry_activity
			}
		}

		// merge everything into the result rows.
		var result:[AdminUserInfo] = []
		for entry in profiles {
			let authorKey = String(RAW_base64.encode(entry.user))
			let found = details[authorKey]
			let activityInfo = activity[authorKey]
			result.append(AdminUserInfo(
				publicKey: authorKey,
				name: found?.name,
				profileID: String(RAW_base64.encode(entry.profileID)),
				profileDate: found?.profileDate,
				readAccessLevels: found?.read ?? [],
				writeAccessLevels: found?.write ?? [],
				eventCount: activityInfo?.count ?? 0,
				lastActivity: activityInfo?.last
			))
		}
		return result
	}

	/// Computes aggregate statistics over the stored events. This only walks the
	/// index tables (never the primary store), so it stays fast on large databases.
	@MDB_transact(.readOnly)
	public func adminEventStats() throws -> AdminEventStats {
		var perKind:[Int:Int] = [:]
		var perApplication:[Int:Int] = [:]
		var perAuthor:[String:Int] = [:]
		var deletionCount = 0
		var accessLevelCount = 0

		// per-kind counts (also derives deletions and access levels).
		try #cursor(TesseraDB.self, database: \.kindIndex) { cursor in
			var iterator:(key:NOSTR_kind, value:NOSTR_id)? = try? cursor.opFirst(returning: (key: NOSTR_kind, value: NOSTR_id).self)
			while let entry = iterator {
				let count = try cursor.dupCount()
				let kindValue = Int(entry.key.RAW_native())
				perKind[kindValue] = count
				if kindValue == 5 { deletionCount = count }
				if kindValue == Int(TesseraKinds.accessLevel.value) { accessLevelCount = count }
				guard let next = try? cursor.opNextNoDup(returning: (key: NOSTR_kind, value: NOSTR_id).self) else { break }
				iterator = next
			}
		}

		// per-application counts.
		try #cursor(TesseraDB.self, database: \.applicationIndex) { cursor in
			var iterator:(key:NOSTR_application, value:NOSTR_id)? = try? cursor.opFirst(returning: (key: NOSTR_application, value: NOSTR_id).self)
			while let entry = iterator {
				let count = try cursor.dupCount()
				perApplication[Int(entry.key.RAW_native())] = count
				guard let next = try? cursor.opNextNoDup(returning: (key: NOSTR_application, value: NOSTR_id).self) else { break }
				iterator = next
			}
		}

		// per-author counts.
		try #cursor(TesseraDB.self, database: \.authorIndex) { cursor in
			var iterator:(key:PublicKey, value:NOSTR_id)? = try? cursor.opFirst(returning: (key: PublicKey, value: NOSTR_id).self)
			while let entry = iterator {
				let count = try cursor.dupCount()
				perAuthor[String(RAW_base64.encode(entry.key))] = count
				guard let next = try? cursor.opNextNoDup(returning: (key: PublicKey, value: NOSTR_id).self) else { break }
				iterator = next
			}
		}

		// date range + recent activity windows (date index is sorted by creation date).
		var oldestEvent:Foundation.Date? = nil
		var newestEvent:Foundation.Date? = nil
		var last24h = 0
		var last7d = 0
		try #cursor(TesseraDB.self, database: \.dateIndex) { cursor in
			if let oldest = try? cursor.opFirst(returning: (key: NOSTR_date, value: NOSTR_id).self) {
				oldestEvent = oldest.key.currentDate()
			}
			guard let newest = try? cursor.opLast(returning: (key: NOSTR_date, value: NOSTR_id).self) else { return }
			newestEvent = newest.key.currentDate()

			let now = UInt64(Date().timeIntervalSince1970)
			let cutoff7d = NOSTR_date(now > 604_800 ? now - 604_800 : 0)
			let cutoff24h = NOSTR_date(now > 86_400 ? now - 86_400 : 0)
			// `opSetRange` fatals when no entry at-or-after the key exists, so only
			// attempt the range scan when the newest event is newer than the cutoff.
			if newest.key >= cutoff7d {
				var date = try cursor.opSetRange(returning: (key: NOSTR_date, value: NOSTR_id).self, key: cutoff7d).key
				while true {
					last7d += 1
					if date >= cutoff24h { last24h += 1 }
					guard let next = try? cursor.opNext(returning: (key: NOSTR_date, value: NOSTR_id).self) else { break }
					date = next.key
				}
			}
		}

		// registered users.
		var userCount = 0
		try #cursor(TesseraDB.self, database: \.userIndex) { cursor in
			var iterator:(key:PublicKey, value:NOSTR_id)? = try? cursor.opFirst(returning: (key: PublicKey, value: NOSTR_id).self)
			while let _ = iterator {
				userCount += 1
				guard let next = try? cursor.opNext(returning: (key: PublicKey, value: NOSTR_id).self) else { break }
				iterator = next
			}
		}

		// replaceable events: distinct keys vs. total revisions (keys are adjacent in the dupsort walk).
		var replaceableEvents = 0
		var replaceableRevisions = 0
		try #cursor(TesseraDB.self, database: \.replaceableEvents) { cursor in
			var sawKey:ReplaceableKey? = nil
			var iterator:(key:ReplaceableKey, value:DatedID)? = try? cursor.opFirst(returning: (key: ReplaceableKey, value: DatedID).self)
			while let entry = iterator {
				if entry.key != sawKey {
					replaceableEvents += 1
					sawKey = entry.key
				}
				replaceableRevisions += 1
				guard let next = try? cursor.opNext(returning: (key: ReplaceableKey, value: DatedID).self) else { break }
				iterator = next
			}
		}

		return AdminEventStats(
			totalEvents: perKind.values.reduce(0, +),
			userCount: userCount,
			perKind: perKind,
			perApplication: perApplication,
			perAuthor: perAuthor,
			oldestEvent: oldestEvent,
			newestEvent: newestEvent,
			last24h: last24h,
			last7d: last7d,
			deletionCount: deletionCount,
			replaceableEvents: replaceableEvents,
			replaceableRevisions: replaceableRevisions,
			accessLevelCount: accessLevelCount,
			databaseFileSize: 0
		)
	}

	/// Lists all kind-1 (access level) events with their level index, name, and author.
	@MDB_transact(.readOnly)
	public func adminListAccessLevels() throws -> [AdminAccessLevelInfo] {
		// collect the ids of all kind-1 events from the kind index.
		var levelIDs:[NOSTR_id] = []
		try #cursor(TesseraDB.self, database: \.kindIndex) { cursor in
			var iterator:(key:NOSTR_kind, value:NOSTR_id)? = try? cursor.opFirst(returning: (key: NOSTR_kind, value: NOSTR_id).self)
			while let entry = iterator {
				if entry.key.RAW_native() == TesseraKinds.accessLevel.value {
					levelIDs.append(entry.value)
					while let next = try? cursor.opNextDup() {
						levelIDs.append(next)
					}
				}
				guard let next = try? cursor.opNextNoDup(returning: (key: NOSTR_kind, value: NOSTR_id).self) else { break }
				iterator = next
			}
		}

		// load each access-level event and extract its tags.
		var result:[AdminAccessLevelInfo] = []
		try #cursor(TesseraDB.self, database: \.signedEvents) { cursor in
			for eventID in levelIDs {
				guard try cursor.containsEntry(key: eventID) else { continue }
				let event = try cursor.opSet(key: eventID)
				guard let levelTag = findTag(tags: event.unsignedEvent.tags.array, as: AccessLevelTag.self) else { continue }
				let name:String
				if let nameTag = findTag(tags: event.unsignedEvent.tags.array, as: AccessLevelNameTag.self) {
					name = String(nameTag.value)
				} else {
					name = ""
				}
				result.append(AdminAccessLevelInfo(
					level: levelTag.value.RAW_native(),
					name: name,
					date: event.unsignedEvent.date.currentDate(),
					author: String(RAW_base64.encode(event.unsignedEvent.publicKey)),
					eventID: String(RAW_base64.encode(event.unsignedEvent.id))
				))
			}
		}
		return result
	}
}

/// Internal helpers for the admin queries.
enum AdminQueriesSupport {
	/// Extracts the display name and access-level sets from a kind-0 profile event.
	static func parseProfileEvent(_ event:TesseraSignedEvent) -> (name:String?, read:[UInt8], write:[UInt8]) {
		var name:String? = nil
		event.unsignedEvent.content.withUnsafeReadableBytes { contentBytes in
			name = User(RAW_decode: UnsafeRawBufferPointer(contentBytes)).map { String($0.userName) }
		}
		if name == nil, let nameTag = findTag(tags: event.unsignedEvent.tags.array, as: StringTag.self), nameTag.indexField.string == "userName" {
			name = String(nameTag.value)
		}
		var read:[UInt8] = []
		var write:[UInt8] = []
		if let readTag = findTag(tags: event.unsignedEvent.tags.array, as: ReadAccessLevels.self) {
			read = readTag.value.RAW_access_immutable(UnsafeBufferPointer<UInt8>.self) { ptr in
				expandBitArray(ptr)
			}
		}
		if let writeTag = findTag(tags: event.unsignedEvent.tags.array, as: WriteAccessLevels.self) {
			write = writeTag.value.RAW_access_immutable(UnsafeBufferPointer<UInt8>.self) { ptr in
				expandBitArray(ptr)
			}
		}
		return (name, read, write)
	}

	/// Expands a 256-bit access-level bit array (32 bytes) into the set of level indices it grants.
	static func expandBitArray(_ ptr:UnsafeBufferPointer<UInt8>) -> [UInt8] {
		var levels:[UInt8] = []
		for (byteIndex, byte) in ptr.enumerated() {
			guard byteIndex < 32 else { break }
			for bitIndex in 0..<8 where (byte & (1 << bitIndex)) != 0 {
				levels.append(UInt8(byteIndex * 8 + bitIndex))
			}
		}
		return levels
	}
}
