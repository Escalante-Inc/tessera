import Testing
import Foundation
import Logging
import RAW
import RAW_base64
import RAW_dh25519
import RAW_ed25519
import bedrock
import QuickLMDB
import NIO
import nostr_kit_swift
import Synchronization
@testable import tessera_core

/// Tests for the admin query layer (`adminListUsers`, `adminEventStats`,
/// `adminListAccessLevels`) and the peer transaction log.
///
/// Uses a dedicated environment name and a temporary directory so it never
/// touches the shared home-directory test database.
@Suite("Admin Queries Tests", .serialized)
final class AdminQueriesTests {

	static let base = Path(FileManager.default.temporaryDirectory.appendingPathComponent("tessera-admin-tests").path)
	static let environment = "tessera-admin-tests"

	let db:TesseraDB
	let cliLogger:Logger

	// actors
	let aliceSigningKey:MemoryGuarded<RAW_ed25519.PrivateKey>
	let bobSigningKey:MemoryGuarded<RAW_ed25519.PrivateKey>
	let alicePublicKey:PublicKey
	let bobPublicKey:PublicKey

	let aliceProfileEvent:TesseraSignedEvent
	let bobProfileEvent:TesseraSignedEvent

	// seeded events
	let aliceRecentEvent:TesseraSignedEvent	// now
	let aliceOldEvent:TesseraSignedEvent	// 30 days ago
	let bobRecentEvent:TesseraSignedEvent	// now
	let accessLevelEvent:TesseraSignedEvent

	init() throws {
		var buildLogger = Logger(label:"\(String(describing:Self.self))")
		buildLogger.logLevel = .error
		cliLogger = buildLogger

		let aliceSecret = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
		let bobSecret = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
		(alicePublicKey, aliceSigningKey) = try RAW_ed25519.generateKeys(secretKey: aliceSecret)
		(bobPublicKey, bobSigningKey) = try RAW_ed25519.generateKeys(secretKey: bobSecret)

		// fresh environment for this suite instance
		try? TesseraDB.deleteEnvironment(base: Self.base, environment: Self.environment, logLevel: .error)
		db = try TesseraDB.openTessera(base: Self.base, memoryMapSize: size_t(Self.base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error, environment: Self.environment)

		// users: alice can read level 0, write level 1; bob reads 0 and 1, writes 2
		aliceProfileEvent = try UnsignedEvent(publicKey: alicePublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [1]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Alice Admin Test"))).sign(as: aliceSigningKey)
		bobProfileEvent = try UnsignedEvent(publicKey: bobPublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0, 1])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [2]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Bob Admin Test"))).sign(as: bobSigningKey)
		try db.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .error)
		try db.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .error)

		let now = Foundation.Date()
		aliceRecentEvent = try UnsignedEvent(publicKey: alicePublicKey, date: NOSTR_date(date: now), tags: [], application: 1, kind: 10000, content: ByteBuffer(string: "alice recent")).sign(as: aliceSigningKey)
		aliceOldEvent = try UnsignedEvent(publicKey: alicePublicKey, date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -30, to: now)!), tags: [], application: 1, kind: 10000, content: ByteBuffer(string: "alice old")).sign(as: aliceSigningKey)
		bobRecentEvent = try UnsignedEvent(publicKey: bobPublicKey, date: NOSTR_date(date: now), tags: [], application: 0, kind: 10001, content: ByteBuffer(string: "bob recent")).sign(as: bobSigningKey)
		try db.scribeNewEvent(signedEvent: aliceRecentEvent, logLevel: .error)
		try db.scribeNewEvent(signedEvent: aliceOldEvent, logLevel: .error)
		try db.scribeNewEvent(signedEvent: bobRecentEvent, logLevel: .error)

		// one kind-1 access level event (level 3, named "Tier 3")
		accessLevelEvent = try UnsignedEvent(publicKey: alicePublicKey, tags: [AccessLevelTag(value: RAW_byte(RAW_native: 3)), AccessLevelNameTag(value: Encoded.String("Tier 3"))], application: 0, kind: 1, content: ByteBuffer()).sign(as: aliceSigningKey)
		try db.scribeNewEvent(signedEvent: accessLevelEvent, logLevel: .error)
	}

	deinit {
		do {
			try TesseraDB.deleteEnvironment(base: Self.base, environment: Self.environment, logLevel: .error)
		} catch {
			print("failed to delete the admin test database at \(Self.base.path())")
		}
	}

	@Test func listUsersReportsNamesLevelsAndActivity() throws {
		let users = try db.adminListUsers()
		#expect(users.count == 2)

		let alice = try #require(users.first { $0.name == "Alice Admin Test" })
		#expect(alice.readAccessLevels == [0])
		#expect(alice.writeAccessLevels == [1])
		#expect(alice.eventCount == 4)	// profile + 2 regular events + access level event
		#expect(alice.lastActivity != nil)

		let bob = try #require(users.first { $0.name == "Bob Admin Test" })
		#expect(bob.readAccessLevels == [0, 1])
		#expect(bob.writeAccessLevels == [2])
		#expect(bob.eventCount == 2)	// profile + 1 regular event
		#expect(bob.lastActivity != nil)
	}

	@Test func deleteUserRemovesRecordAndProfile() throws {
		// sanity: bob is visible before the deletion
		let before = try db.adminListUsers()
		#expect(before.contains { $0.name == "Bob Admin Test" })
		let statsBefore = try db.adminEventStats()

		try db.adminDeleteUser(publicKey: bobPublicKey, logLevel: .error)

		// the user is gone from admin surfaces
		let after = try db.adminListUsers()
		#expect(!after.contains { $0.name == "Bob Admin Test" })

		// exactly the profile event was removed (bob's regular events stay)
		let statsAfter = try db.adminEventStats()
		#expect(statsAfter.totalEvents == statsBefore.totalEvents - 1)
		#expect(statsAfter.userCount == statsBefore.userCount - 1)

		// deleting the same user again throws (the record no longer exists)
		do {
			try db.adminDeleteUser(publicKey: bobPublicKey, logLevel: .error)
			Issue.record("expected deleting a missing user to throw")
		} catch {}
	}

	@Test func listUsersActivityFreshness() throws {
		let users = try db.adminListUsers()
		let alice = try #require(users.first { $0.name == "Alice Admin Test" })
		let lastActivity = try #require(alice.lastActivity)
		// the most recent alice event is 'now' (the old one is 30 days back)
		#expect(abs(Date().timeIntervalSince(lastActivity)) < 60)
	}

	@Test func eventStatsAreAccurate() throws {
		let stats = try db.adminEventStats()
		// 3 users' profile events (2) + 3 regular + 1 access level = 6
		#expect(stats.totalEvents == 6)
		#expect(stats.userCount == 2)
		#expect(stats.accessLevelCount == 1)
		#expect(stats.deletionCount == 0)
		#expect(stats.perKind[Int(TesseraKinds.user.value)] == 2)
		#expect(stats.perKind[10000] == 2)
		#expect(stats.perKind[10001] == 1)
		#expect(stats.perKind[Int(TesseraKinds.accessLevel.value)] == 1)
		#expect(stats.perApplication[1] == 2)
		#expect(stats.perApplication[0] == 4)

		let aliceKey = String(RAW_base64.encode(alicePublicKey))
		#expect(stats.perAuthor[aliceKey] == 4)	// profile + 2 regular + access level
		let bobKey = String(RAW_base64.encode(bobPublicKey))
		#expect(stats.perAuthor[bobKey] == 2)	// profile + 1 regular

		// oldest is the 30-day-old alice event; newest is one of the 'now' events
		let oldest = try #require(stats.oldestEvent)
		let newest = try #require(stats.newestEvent)
		#expect(oldest < newest)
		#expect(newest.timeIntervalSinceNow < 60)
		#expect(stats.last7d >= 3)
		#expect(stats.last24h >= 2)	// alice recent + bob recent (profiles are also 'now')

		// replaceable index: alice's kind-10000 events collapse to one
		// (publicKey, kind) key with 2 revisions; bob's kind-30000 (with a
		// d-tag) is a second key with 1 revision. Profile/kind-1 events are
		// non-replaceable.
		#expect(stats.replaceableEvents == 2)
		#expect(stats.replaceableRevisions == 3)
	}

	@Test func listAccessLevels() throws {
		let levels = try db.adminListAccessLevels()
		#expect(levels.count == 1)
		let level = try #require(levels.first)
		#expect(level.level == 3)
		#expect(level.name == "Tier 3")
		#expect(level.author == String(RAW_base64.encode(alicePublicKey)))
		#expect(level.eventID == String(RAW_base64.encode(accessLevelEvent.unsignedEvent.id)))
	}

	@Test func emptyDatabaseReportsZeroes() throws {
		// a second environment with nothing scribed
		let emptyBase = Path(FileManager.default.temporaryDirectory.appendingPathComponent("tessera-admin-tests-empty").path)
		try? TesseraDB.deleteEnvironment(base: emptyBase, environment: Self.environment, logLevel: .error)
		defer { try? TesseraDB.deleteEnvironment(base: emptyBase, environment: Self.environment, logLevel: .error) }
		let emptyDB = try TesseraDB.openTessera(base: emptyBase, memoryMapSize: size_t(emptyBase.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error, environment: Self.environment)
		let stats = try emptyDB.adminEventStats()
		#expect(stats.totalEvents == 0)
		#expect(stats.userCount == 0)
		#expect(stats.oldestEvent == nil)
		#expect(stats.newestEvent == nil)
		let users = try emptyDB.adminListUsers()
		#expect(users.isEmpty)
	}
}

/// Tests for the JSONL peer transaction log (append, read, rotation).
@Suite("Peer Transaction Log Tests", .serialized)
final class PeerTransactionLogTests {

	static let base = Path(FileManager.default.temporaryDirectory.appendingPathComponent("tessera-txlog-tests").path)

	deinit {
		try? FileManager.default.removeItem(atPath: Self.base.path())
	}

	@Test func appendAndReadRoundtrip() throws {
		try FileManager.default.createDirectory(atPath: Self.base.path(), withIntermediateDirectories: true)
		let log = PeerTransactionLog(base: Self.base, logLevel: .error)

		log.record(peer: "peerA", direction: "inbound", type: "event", detail: "scribed kind 1000")
		log.record(peer: "peerB", direction: "outbound", type: "req", detail: "served 4 events")
		log.record(peer: "peerA", direction: "bidirectional", type: "sync", detail: "concord round complete")

		let records = log.read(limit: 10)
		#expect(records.count == 3)
		// newest first
		#expect(records[0].peer == "peerA")
		#expect(records[0].direction == "bidirectional")
		#expect(records[0].detail.contains("concord"))
		#expect(records[1].peer == "peerB")
		#expect(records[1].type == "req")
		#expect(records[2].type == "event")
	}

	@Test func readLimitReturnsMostRecent() throws {
		try FileManager.default.createDirectory(atPath: Self.base.path(), withIntermediateDirectories: true)
		let log = PeerTransactionLog(base: Self.base, logLevel: .error)
		for index in 0..<10 {
			log.record(peer: "p\(index)", direction: "inbound", type: "event", detail: "record \(index)")
		}
		let records = log.read(limit: 3)
		#expect(records.count == 3)
		// newest first
		#expect(records[0].peer == "p9")
		#expect(records[2].peer == "p7")
	}

	@Test func rotationKeepsTail() throws {
		try FileManager.default.createDirectory(atPath: Self.base.path(), withIntermediateDirectories: true)
		// a tiny threshold forces a rotation after a few records
		let log = PeerTransactionLog(base: Self.base, logLevel: .error, maxBytes: 512, keepOnRotate: 4)
		for index in 0..<20 {
			log.record(peer: "p\(index)", direction: "inbound", type: "event", detail: "rotation test record number \(index) with some padding to grow the line")
		}
		let records = log.read(limit: 100)
		#expect(records.count == 4)
		// newest first: the most recent record leads the tail
		#expect(records[0].peer == "p19")
	}
}
