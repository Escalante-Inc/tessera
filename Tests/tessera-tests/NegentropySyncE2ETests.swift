import Testing
import Logging
import Foundation
import NIO
import RAW
import RAW_base64
import RAW_dh25519
import RAW_ed25519
import bedrock
import bedrock_fifo
import QuickLMDB
import nostr_kit_swift
import wireguard_userspace_nio
import concord
@testable import tessera_core

/// Builds a string-valued `EventTag` with the given index field (tag name).
fileprivate func genericRefTag(_ name: String, _ value: String) -> EventTag {
	EventTag(indexField: NOSTR_tag_name(string: name)!, value: NOSTR_tag_generic_value(value))
}

/// Builds a `p` (pubkey reference) `EventTag` for the given public key.
fileprivate func userRefTag(_ key: PublicKey) -> EventTag {
	EventTag(indexField: NOSTR_tag_name(string: "p")!, value: NOSTR_tag_generic_value(String(RAW_base64.encode(key))))
}

@Suite("Negentropy Sync E2E Tests", .serialized)
final class NegentropySyncE2ETests {

	let base = Path(FileManager.default.homeDirectoryForCurrentUser.path)

	static let aliceStaticPrivateKey = memoryGuardedKey(fromBase64: "8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI=")
	static let bobStaticPrivateKey = memoryGuardedKey(fromBase64: "SD/y8yQa/DgiYRnDI9vJEiGezNn4yLd/4yL9OLnej0A=")

	let alicePrivateKey: MemoryGuarded<RAW_dh25519.PrivateKey>
	let bobPrivateKey: MemoryGuarded<RAW_dh25519.PrivateKey>
	let alicePublicKey: PublicKey
	let bobPublicKey: PublicKey

	let aliceEd25519PublicKey: PublicKey
	let aliceEd25519PrivateKey: MemoryGuarded<RAW_ed25519.PrivateKey>
	let bobEd25519PublicKey: PublicKey
	let bobEd25519PrivateKey: MemoryGuarded<RAW_ed25519.PrivateKey>

	let aliceDB: TesseraDB
	let bobDB: TesseraDB

	let aliceProfileEvent: TesseraSignedEvent
	let bobProfileEvent: TesseraSignedEvent
	let aliceNoteEvent: TesseraSignedEvent
	let bobNoteEvent: TesseraSignedEvent

	init() throws {
		alicePrivateKey = Self.aliceStaticPrivateKey
		bobPrivateKey = Self.bobStaticPrivateKey
		(alicePublicKey, _) = (PublicKey(privateKey: Self.aliceStaticPrivateKey), Self.aliceStaticPrivateKey)
		(bobPublicKey, _) = (PublicKey(privateKey: Self.bobStaticPrivateKey), Self.bobStaticPrivateKey)
		(aliceEd25519PublicKey, aliceEd25519PrivateKey) = try RAW_ed25519.generateKeys(secretKey: alicePrivateKey)
		(bobEd25519PublicKey, bobEd25519PrivateKey) = try RAW_ed25519.generateKeys(secretKey: bobPrivateKey)

		// Two entirely independent tessera databases.
		try? TesseraDB.deleteEnvironment(base: base, environment: "aliceSync", logLevel: .error)
		try? TesseraDB.deleteEnvironment(base: base, environment: "bobSync", logLevel: .error)
		aliceDB = try TesseraDB.openTessera(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error, environment: "aliceSync")
		bobDB = try TesseraDB.openTessera(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error, environment: "bobSync")

		// Alice's database: a user + one note unique to her.
		aliceProfileEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [1]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "SyncAlice"))).sign(as: aliceEd25519PrivateKey)
		aliceNoteEvent = try UnsignedEvent(
			publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -1, to: Date())!),
			tags: [userRefTag(bobEd25519PublicKey), genericRefTag("sync", "alice-only")], application: 0,
			kind: 10000, content: ByteBuffer(string: "Alice sync content")).sign(as: aliceEd25519PrivateKey)
		try aliceDB.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .error)
		try aliceDB.scribeNewEvent(signedEvent: aliceNoteEvent, logLevel: .error)

		// Bob's database: a user + one note unique to him.
		bobProfileEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0,1])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [0,2]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "SyncBob"))).sign(as: bobEd25519PrivateKey)
		bobNoteEvent = try UnsignedEvent(
			publicKey: bobEd25519PublicKey, date: NOSTR_date(date: Date()),
			tags: [userRefTag(aliceEd25519PublicKey), genericRefTag("sync", "bob-only"), DTag(value: "bobUniqueDTag")], application: 1,
			kind: 30000, content: ByteBuffer(string: "Bob sync content")).sign(as: bobEd25519PrivateKey)
		try bobDB.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .error)
		try bobDB.scribeNewEvent(signedEvent: bobNoteEvent, logLevel: .error)
	}

	deinit {
		do { try TesseraDB.deleteEnvironment(base: base, environment: "aliceSync", logLevel: .trace) } catch {}
		do { try TesseraDB.deleteEnvironment(base: base, environment: "bobSync", logLevel: .trace) } catch {}
	}

	/// Runs one full two-way concord sync round between alice and bob over
	/// two real loopback WireGuard interfaces, then returns.
	///
	/// No fixed sleeps: both sides run `runConcordRoundAsync`, each on its own
	/// dedicated thread, and each round self-terminates when the peer's
	/// `.finish` arrives — awaiting both is a deterministic completion signal,
	/// exactly as in the concord engine's own live tests.
	private func syncOnce() async throws {
		try await self.syncOnce(alice: aliceDB, bob: bobDB)
	}

	/// Generalized form of `syncOnce()` used when the two peers are not the
	/// default alice/bob databases (e.g. empty-DB edge cases). The WireGuard
	/// interfaces always use alice/bob's loopback endpoints; only the databases
	/// that the concord rounds reconcile differ.
	private func syncOnce(alice aDB: TesseraDB, bob bDB: TesseraDB) async throws {
		var logger = Logger(label: "concord-e2e")
		logger.logLevel = .error

		let bobFifo = FIFO<ByteBuffer, Swift.Error>()
		let alicePeers = [(PeerInfo(publicKey: bobPublicKey, ipAddress: "127.0.0.1", port: 47101, internalKeepAlive: .seconds(20), inboundData: bobFifo))]
		let aliceInterface = try WGInterface<KCPChannels>(staticPrivateKey: alicePrivateKey, mtu: 1400, initialConfiguration: alicePeers, logLevel: .error, listeningPort: 47100)

		let aliceFifo = FIFO<ByteBuffer, Swift.Error>()
		let bobPeers = [(PeerInfo(publicKey: alicePublicKey, ipAddress: "127.0.0.1", port: 47100, internalKeepAlive: .seconds(20), inboundData: aliceFifo))]
		let bobInterface = try WGInterface<KCPChannels>(staticPrivateKey: bobPrivateKey, mtu: 1400, initialConfiguration: bobPeers, logLevel: .error, listeningPort: 47101)

		_ = try await withThrowingTaskGroup(of: Void.self, body: { group in
			group.addTask { try await aliceInterface.run() }
			group.addTask { try await bobInterface.run() }
			try await aliceInterface.waitForChannelInit()
			try await bobInterface.waitForChannelInit()

			// Role tie-break is the same anti-symmetric comparison the sync
			// manager makes: the lexicographically greater WireGuard public key
			// is the initiator. Computing it once keeps both sides consistent.
			let aliceIsInitiator = alicePublicKey > bobPublicKey
			// Hoist self properties to locals so the sending task closures
			// capture only Sendable values (never `self`).
			let aliceSyncPublicKey = alicePublicKey
			let bobSyncPublicKey = bobPublicKey

			// Both sides hand off to `runConcordRoundAsync`, which parks the
			// async task and runs the blocking LMDB round on a dedicated thread.
			// Each continuation resumes exactly when its round terminates, so
			// awaiting both is deterministic — no fixed sleeps.
			let aliceChannel = try await aliceInterface.getChannel()
			let bobChannel = try await bobInterface.getChannel()

			let aliceRound = Task<Void, Swift.Error> {
				try await runConcordRoundAsync(
					env: aDB.syncEnvironment,
					role: aliceIsInitiator ? .initiator : .responder,
					transport: ConcordWGTransport<NOSTR_id, TesseraSignedEvent>(
						channel: aliceChannel,
						peerPublicKey: bobSyncPublicKey,
						syncFIFO: bobFifo
					)
				)
			}
			let bobRound = Task<Void, Swift.Error> {
				try await runConcordRoundAsync(
					env: bDB.syncEnvironment,
					role: aliceIsInitiator ? .responder : .initiator,
					transport: ConcordWGTransport<NOSTR_id, TesseraSignedEvent>(
						channel: bobChannel,
						peerPublicKey: aliceSyncPublicKey,
						syncFIFO: aliceFifo
					)
				)
			}
			_ = try await aliceRound.value
			_ = try await bobRound.value
			group.cancelAll()
			try await group.waitForAll()
		})
	}

	/// Counts events matching the union of both sides' ids.
	private func countUnion(_ db: TesseraDB, user: PublicKey? = nil) throws -> Int {
		return try db.queryEventsBySmartFilter(filters: [Filter(ids: [aliceNoteEvent.unsignedEvent.id, bobNoteEvent.unsignedEvent.id, aliceProfileEvent.unsignedEvent.id, bobProfileEvent.unsignedEvent.id])], user: user).count
	}

	/// Synchronous wrapper for `getFilterEligibleIds`, since transaction-bound
	/// QuickLMDB calls are marked `@available(*, noasync)` and therefore cannot be
	/// invoked directly from an `async` test function.
	private func eligibleIDs(_ db: TesseraDB, filter: Filter, includeAuthors: Bool = false) throws -> Set<NOSTR_id> {
		let ids = try db.getFilterEligibleIds(filters: [filter])
		return includeAuthors ? ids.0.union(ids.1) : ids.0
	}

	// MARK: - Baseline tests

	/// After a sync, both databases contain BOTH side's events (convergence).
	@Test func syncConvergesBothWays() async throws {
		#expect(aliceDB.eventCount == 2)
		#expect(bobDB.eventCount == 2)
		try await syncOnce()
		try aliceDB.reindexAfterSync(logLevel: .error)
		try bobDB.reindexAfterSync(logLevel: .error)
		#expect(aliceDB.eventCount == 4)
		#expect(bobDB.eventCount == 4)
	}

	/// After a sync, the reindex pass makes the synced events visible to the
	/// query engine (the whole point of `reindexAfterSync`).
	@Test func syncedEventsAreQueryableAfterReindex() async throws {
		try await syncOnce()
		try aliceDB.reindexAfterSync(logLevel: .error)
		try bobDB.reindexAfterSync(logLevel: .error)

		// Bob's event is now present on Alice, indexed by each of the five indexes.
		let aliceSeesBob = try aliceDB.queryEventsBySmartFilter(filters: [Filter(ids: [bobNoteEvent.unsignedEvent.id])])
		#expect(aliceSeesBob.count == 1)
		// Alice's event is now present on Bob, queryable by author and by date.
		let bobSeesAlice = try bobDB.queryEventsBySmartFilter(filters: [Filter(ids: [aliceNoteEvent.unsignedEvent.id])])
		#expect(bobSeesAlice.count == 1)
		// Synced events are also reachable through the author index.
		let aliceByAuthor = try eligibleIDs(aliceDB, filter: Filter(authors: [bobEd25519PublicKey]))
		#expect(aliceByAuthor.contains(bobNoteEvent.unsignedEvent.id))
	}

	/// Synced values that fail verification (stored key does not match the
	/// event's computed id) are dropped by the reindex pass rather than
	/// poisoning the store.
	@Test func reindexDropsTamperedValues() throws {
		// Directly inject an entry into alice's signedEvents, bypassing the
		// scribe path (as a malicious sync peer would), stored under a key that
		// deliberately does NOT match the event's own id.
		let tampered = try UnsignedEvent(
			publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Date()),
			tags: [], application: 0, kind: 10000, content: ByteBuffer(string: "tampered")).sign(as: aliceEd25519PrivateKey)
		let randomKeyBytes = try generateSecureRandomBytes(count: 32)
		let randomKey = NOSTR_id(RAW_decode: randomKeyBytes.withUnsafeBytes { $0 })!
		#expect(randomKey != tampered.unsignedEvent.id)
		let trans = try Transaction<Write>(env: aliceDB.env)
		try aliceDB.signedEvents.setEntry(key: randomKey, value: tampered, flags: [], tx: trans)
		try trans.commit()
		#expect(aliceDB.eventCount == 3)

		try aliceDB.reindexAfterSync(logLevel: .error)
		// The id==key mismatch (plus re-verification) removes exactly the
		// injected entry; alice's own two events survive untouched.
		#expect(aliceDB.eventCount == 2)
	}

	/// A parameterized-replaceable event (kind 30_000..<40_000) missing its
	/// required d-tag can only reach the store via a raw sync. It cannot be
	/// indexed (`ReplaceableKey(event:)` throws for it), so the reindex must
	/// DROP it instead of aborting the whole reindex pass.
	@Test func reindexDropsParameterizedEventMissingDTag() throws {
		let malformed = try UnsignedEvent(
			publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Date()),
			tags: [], application: 0, kind: 30000, content: ByteBuffer(string: "missing d-tag")).sign(as: aliceEd25519PrivateKey)
		// Sanity: ReplaceableKey really cannot be built for this event, and it
		// cannot be scribed through the normal path.
		#expect((try? ReplaceableKey(event: malformed.unsignedEvent)) == nil)
		#expect(throws: SignedNoteError.invalidParameterizedEvent) {
			try aliceDB.scribeNewEvent(signedEvent: malformed, logLevel: .error)
		}

		// A raw sync peer, however, can place it directly into signedEvents.
		let trans = try Transaction<Write>(env: aliceDB.env)
		try aliceDB.signedEvents.setEntry(key: malformed.unsignedEvent.id, value: malformed, flags: [], tx: trans)
		try trans.commit()
		#expect(aliceDB.eventCount == 3)

		// Reindex must succeed (not abort) and must drop the unindexable event.
		try aliceDB.reindexAfterSync(logLevel: .error)
		#expect(aliceDB.eventCount == 2)
	}

	// MARK: - Edge cases

	/// One side has zero events; the negentropy zero-DB reconcile still
	/// converges (mirrors the library's `syncWithEmptyDB`).
	@Test func syncWithEmptyDatabaseConverges() async throws {
		// A fresh, entirely empty bob-side database.
		try? TesseraDB.deleteEnvironment(base: base, environment: "bobEmpty", logLevel: .error)
		let bobEmpty = try TesseraDB.openTessera(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error, environment: "bobEmpty")
		defer { try? TesseraDB.deleteEnvironment(base: base, environment: "bobEmpty", logLevel: .trace) }

		#expect(bobEmpty.eventCount == 0)
		try await self.syncOnce(alice: aliceDB, bob: bobEmpty)
		try aliceDB.reindexAfterSync(logLevel: .error)
		try bobEmpty.reindexAfterSync(logLevel: .error)
		// Alice's 2 events flow to the empty peer; the empty peer gives nothing back.
		#expect(aliceDB.eventCount == 2)
		#expect(bobEmpty.eventCount == 2)
	}

	/// Empty database on the INITIATOR side also converges.
	@Test func syncEmptyInitiatorConverges() async throws {
		try? TesseraDB.deleteEnvironment(base: base, environment: "aliceEmpty", logLevel: .error)
		let aliceEmpty = try TesseraDB.openTessera(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error, environment: "aliceEmpty")
		defer { try? TesseraDB.deleteEnvironment(base: base, environment: "aliceEmpty", logLevel: .trace) }

		try await self.syncOnce(alice: aliceEmpty, bob: bobDB)
		try aliceEmpty.reindexAfterSync(logLevel: .error)
		try bobDB.reindexAfterSync(logLevel: .error)
		#expect(aliceEmpty.eventCount == 2)
		#expect(bobDB.eventCount == 2)
	}

	/// A replaceable event synced from the peer does NOT shadow the local newer
	/// version. Both store the raw events, but the smart filter resolves to the
	/// newest for the same replaceable key.
	@Test func syncKeepsNewestReplaceableEvent() async throws {
		// Alice authors an older replaceable event (kind 10000 = PK-replaceable).
		let oldDate = NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -10, to: Date())!)
		let aliceOld = try UnsignedEvent(
			publicKey: aliceEd25519PublicKey, date: oldDate,
			tags: [], application: 0, kind: 10000, content: ByteBuffer(string: "old version")).sign(as: aliceEd25519PrivateKey)
		// Bob authors a NEWER event for the SAME replaceable key (same author, same kind).
		let newDate = NOSTR_date(date: Date())
		let bobNew = try UnsignedEvent(
			publicKey: aliceEd25519PublicKey, date: newDate,
			tags: [], application: 0, kind: 10000, content: ByteBuffer(string: "new version")).sign(as: aliceEd25519PrivateKey)
		#expect(aliceOld.unsignedEvent.id != bobNew.unsignedEvent.id)

		// Each peer knows the other's author (users are replicated across relays),
		// so no DB rejects writes from the shared author.
		try aliceDB.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .error)
		try bobDB.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .error)
		try aliceDB.scribeNewEvent(signedEvent: aliceOld, logLevel: .error)
		try bobDB.scribeNewEvent(signedEvent: bobNew, logLevel: .error)

		try await syncOnce()
		try aliceDB.reindexAfterSync(logLevel: .error)
		try bobDB.reindexAfterSync(logLevel: .error)

		// Raw store contains everything on both sides: 2 users + aliceNote +
		// bobNote + aliceOld + bobNew.
		#expect(aliceDB.eventCount == 6)
		#expect(bobDB.eventCount == 6)

		// Smart filter: exactly the NEWEST event survives for the replaceable key.
		let aliceNewest = try aliceDB.queryEventsBySmartFilter(filters: [Filter(ids: [aliceOld.unsignedEvent.id, bobNew.unsignedEvent.id])])
		#expect(aliceNewest.count == 1)
		#expect(aliceNewest[0].unsignedEvent.id == bobNew.unsignedEvent.id)
		let bobNewest = try bobDB.queryEventsBySmartFilter(filters: [Filter(ids: [aliceOld.unsignedEvent.id, bobNew.unsignedEvent.id])])
		#expect(bobNewest.count == 1)
		#expect(bobNewest[0].unsignedEvent.id == bobNew.unsignedEvent.id)
	}

	/// Kind-5 deletion events sync across peers and make the deleted event
	/// disappear from smart-filter queries on BOTH sides.
	@Test func syncPropagatesKind5Deletion() async throws {
		// Bob authors a normal replaceable event.
		let victim = try UnsignedEvent(
			publicKey: bobEd25519PublicKey, date: NOSTR_date(date: Date()),
			tags: [userRefTag(aliceEd25519PublicKey)], application: 0, kind: 10000, content: ByteBuffer(string: "victim")).sign(as: bobEd25519PrivateKey)
		// Bob also authors a kind-5 deletion of it.
		let deletion = try UnsignedEvent(
			publicKey: bobEd25519PublicKey, date: NOSTR_date(date: Date()),
			tags: [EventRefTag(value: victim.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: bobEd25519PrivateKey)
		try bobDB.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .error)
		try bobDB.scribeNewEvent(signedEvent: victim, logLevel: .error)
		try bobDB.scribeNewEvent(signedEvent: deletion, logLevel: .error)

		// Alice only has Bob's new event, not the deletion yet.
		try aliceDB.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .error)
		try aliceDB.scribeNewEvent(signedEvent: victim, logLevel: .error)
		let preDelete = try aliceDB.queryEventsBySmartFilter(filters: [Filter(ids: [victim.unsignedEvent.id])])
		#expect(preDelete.count == 1)

		try await syncOnce()
		try aliceDB.reindexAfterSync(logLevel: .error)
		try bobDB.reindexAfterSync(logLevel: .error)

		// The victim is now hidden on BOTH sides; the deletion event synced over.
		let alicePostDelete = try aliceDB.queryEventsBySmartFilter(filters: [Filter(ids: [victim.unsignedEvent.id])])
		#expect(alicePostDelete.isEmpty)
		let bobPostDelete = try bobDB.queryEventsBySmartFilter(filters: [Filter(ids: [victim.unsignedEvent.id])])
		#expect(bobPostDelete.isEmpty)
	}

	/// Two consecutive sync rounds are idempotent: the second round transfers
	/// nothing and leaves the databases in the same state.
	@Test func doubleSyncIsIdempotent() async throws {
		try await syncOnce()
		try aliceDB.reindexAfterSync(logLevel: .error)
		try bobDB.reindexAfterSync(logLevel: .error)
		let aliceCountAfterFirst = aliceDB.eventCount
		let bobCountAfterFirst = bobDB.eventCount
		#expect(aliceCountAfterFirst == 4)
		#expect(bobCountAfterFirst == 4)

		try await syncOnce()
		try aliceDB.reindexAfterSync(logLevel: .error)
		try bobDB.reindexAfterSync(logLevel: .error)
		#expect(aliceDB.eventCount == aliceCountAfterFirst)
		#expect(bobDB.eventCount == bobCountAfterFirst)
	}

	// MARK: - Scale tests

	/// A larger dataset (100+ events per side with partial overlap) converges,
	/// and the reindex keeps all five indexes consistent at scale.
	@Test func syncLargeDatasetConverges() async throws {
		// Cross-register the shared author so both relays accept each side's notes.
		try aliceDB.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .error)
		try bobDB.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .error)

		// 120 alice-authored events, 120 bob-authored events, 30 shared between them.
		var aliceIDs: [NOSTR_id] = []
		var bobIDs: [NOSTR_id] = []
		var sharedIDs: [NOSTR_id] = []

		let dayBase = Calendar.current.date(byAdding: .day, value: -30, to: Date())!
		for i in 0..<120 {
			let date = NOSTR_date(date: dayBase.addingTimeInterval(TimeInterval(i) * 3600))
			let ev = try UnsignedEvent(
				publicKey: aliceEd25519PublicKey, date: date,
				tags: [userRefTag(bobEd25519PublicKey), genericRefTag("scale", "alice-\(i)"), genericRefTag("common", "a")], application: 0,
				kind: 1000, content: ByteBuffer(string: "alice bulk \(i)")).sign(as: aliceEd25519PrivateKey)
			try aliceDB.scribeNewEvent(signedEvent: ev, logLevel: .error)
			aliceIDs.append(ev.unsignedEvent.id)
			// Every 4th event is also known to (pre-seeded on) bob.
			if i % 4 == 0 {
				try bobDB.scribeNewEvent(signedEvent: ev, logLevel: .error)
				sharedIDs.append(ev.unsignedEvent.id)
			}
		}
		for i in 0..<120 {
			let date = NOSTR_date(date: dayBase.addingTimeInterval(TimeInterval(i) * 3600))
			let ev = try UnsignedEvent(
				publicKey: bobEd25519PublicKey, date: date,
				tags: [userRefTag(aliceEd25519PublicKey), genericRefTag("scale", "bob-\(i)"), genericRefTag("common", "b")], application: 0,
				kind: 1000, content: ByteBuffer(string: "bob bulk \(i)")).sign(as: bobEd25519PrivateKey)
			try bobDB.scribeNewEvent(signedEvent: ev, logLevel: .error)
			bobIDs.append(ev.unsignedEvent.id)
		}

		// Pre-sync counts: each DB has the 2 users + 1 synced note from the base
		// suite, then its own events. Alice: 2 users + aliceNote + 120 notes.
		// Bob: 2 users + bobNote + 30 shared + 120 notes.
		#expect(aliceDB.eventCount == 3 + 120)
		#expect(bobDB.eventCount == 3 + 30 + 120)

		try await syncOnce()
		try aliceDB.reindexAfterSync(logLevel: .error)
		try bobDB.reindexAfterSync(logLevel: .error)

		// Full convergence: both users + both base notes + all 240 bulk events.
		let total = 4 + 240
		#expect(aliceDB.eventCount == total)
		#expect(bobDB.eventCount == total)

		// Both sides now hold the union, queryable through the batch id filter.
		let allIDs = aliceIDs + bobIDs
		let aliceUnion = try aliceDB.queryEventsBySmartFilter(filters: [Filter(ids: allIDs, limit: NOSTR_filter_limit(RAW_native: 250))])
		#expect(aliceUnion.count == allIDs.count)
		let bobUnion = try bobDB.queryEventsBySmartFilter(filters: [Filter(ids: allIDs, limit: NOSTR_filter_limit(RAW_native: 250))])
		#expect(bobUnion.count == allIDs.count)

		// Shared events were NOT duplicated by the sync (still exactly one copy).
		for id in sharedIDs {
			let n = try eligibleIDs(aliceDB, filter: Filter(ids: [id])).count
			#expect(n == 1)
		}
	}

	/// Events carrying many tags reindex cleanly and remain tag-queryable after
	/// a sync (stress for the tag index).
	@Test func syncTagHeavyEventsStayQueryable() async throws {
		try aliceDB.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .error)
		try bobDB.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .error)

		var tags: [EventTag] = []
		for i in 0..<24 {
			tags.append(genericRefTag("tag-\(i % 6)", "value-\(i)"))
		}
		// Kind 1000 is non-replaceable (no d-tag needed), so the tag stress is
		// what's exercised here.
		let heavy = try UnsignedEvent(
			publicKey: bobEd25519PublicKey, date: NOSTR_date(date: Date()),
			tags: tags, application: 0, kind: 1000, content: ByteBuffer(string: "tag heavy")).sign(as: bobEd25519PrivateKey)
		try bobDB.scribeNewEvent(signedEvent: heavy, logLevel: .error)

		try await syncOnce()
		try aliceDB.reindexAfterSync(logLevel: .error)
		try bobDB.reindexAfterSync(logLevel: .error)

		// Queryable on alice through every one of the 6 distinct tag names.
		for i in 0..<6 {
			let hits = try aliceDB.queryEventsBySmartFilter(filters: [Filter(tags: [genericRefTag("tag-\(i)", "value-\(i)")])])
			#expect(hits.count == 1)
			#expect(hits[0].unsignedEvent.id == heavy.unsignedEvent.id)
		}
	}

	// MARK: - Scaling / complexity

	/// Builds a fresh, isolated pair of databases pre-seeded with `n` mutually
	/// disjoint events per side (each author scribing only onto their own DB).
	/// Both peers share the two user-profile events, so the only difference to
	/// reconcile is the `n` events on each side — the worst case for negentropy
	/// (maximal symmetric difference).
	private func makeScalePair(_ n: Int, suffix: String) throws -> (TesseraDB, TesseraDB) {
		let envA = "aliceScale\(suffix)"
		let envB = "bobScale\(suffix)"
		try? TesseraDB.deleteEnvironment(base: base, environment: envA, logLevel: .error)
		try? TesseraDB.deleteEnvironment(base: base, environment: envB, logLevel: .error)
		let a = try TesseraDB.openTessera(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error, environment: envA)
		let b = try TesseraDB.openTessera(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error, environment: envB)
		try a.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .error)
		try a.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .error)
		try b.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .error)
		try b.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .error)
		if n > 0 {
			let dayBase = Calendar.current.date(byAdding: .day, value: -30, to: Date())!
			for i in 0..<n {
				let date = NOSTR_date(date: dayBase.addingTimeInterval(TimeInterval(i) * 60))
				let aliceEv = try UnsignedEvent(
					publicKey: aliceEd25519PublicKey, date: date,
					tags: [genericRefTag("scale", "a-\(i)")], application: 0,
					kind: 1000, content: ByteBuffer(string: "scale alice \(i)")).sign(as: aliceEd25519PrivateKey)
				try a.scribeNewEvent(signedEvent: aliceEv, logLevel: .error)
				let bobEv = try UnsignedEvent(
					publicKey: bobEd25519PublicKey, date: date,
					tags: [genericRefTag("scale", "b-\(i)")], application: 0,
					kind: 1000, content: ByteBuffer(string: "scale bob \(i)")).sign(as: bobEd25519PrivateKey)
				try b.scribeNewEvent(signedEvent: bobEv, logLevel: .error)
			}
		}
		return (a, b)
	}

	/// Times a full sync round between a fresh `n`-per-side pair, repeated a
	/// few times, returning the MINIMUM wall time in seconds. The minimum is
	/// the fair estimator: scheduler noise can only slow a run down, never
	/// speed it up, so the min is the truest measure of the protocol work.
	private func measureSyncSeconds(sizes: [Int]) async throws -> [Double] {
		var results: [Double] = []
		for (idx, n) in sizes.enumerated() {
			var best = Double.infinity
			let repeats = n <= 200 ? 3 : 2
			for rep in 0..<repeats {
				let (a, b) = try self.makeScalePair(n, suffix: "\(idx)_\(rep)")
				defer {
					try? TesseraDB.deleteEnvironment(base: base, environment: "aliceScale\(idx)_\(rep)", logLevel: .trace)
					try? TesseraDB.deleteEnvironment(base: base, environment: "bobScale\(idx)_\(rep)", logLevel: .trace)
				}
				let clock = ContinuousClock()
				let start = clock.now
				try await self.syncOnce(alice: a, bob: b)
				let d = start.duration(to: clock.now)
				let secs = Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
				best = Swift.min(best, secs)
			}
			results.append(best)
		}
		return results
	}

	/// Verifies the sync runtime does NOT grow exponentially with database
	/// size. Measures full sync rounds at increasing sizes, subtracts the
	/// fixed per-round overhead (WG handshake + channel init, captured at
	/// size 0), then checks:
	///   - every per-doubling time ratio stays below 6 (polynomial bound:
	///     linear ≈ 2, quadratic ≈ 4; exponential ratios grow without bound),
	///   - the fitted log2 growth exponent stays below 2 (linear ⇒ ≈1,
	///     quadratic ⇒ ≈2, exponential ⇒ large and increasing).
	/// Ambiguity guard: negentropy achieves O(difference) communication, so a
	/// disjoint dataset is the correct worst-case benchmark.
	@Test func syncScalesSubExponentiallyWithDatabaseSize() async throws {
		let sizes = [0, 200, 400, 800, 1600]
		let times = try await self.measureSyncSeconds(sizes: sizes)

		let fixed = times[0]
		var adjusted: [Double] = []
		for i in 1..<sizes.count {
			adjusted.append(Swift.max(times[i] - fixed, 1e-9))
		}
		var ratios: [Double] = []
		for i in 1..<adjusted.count {
			ratios.append(adjusted[i] / adjusted[i - 1])
		}
		var logSum = 0.0
		for r in ratios { logSum += Foundation.log2(r) }
		let exponent = logSum / Double(ratios.count)

		// Report the measured table + fit for inspection in the test log.
		print("— negentropy sync scaling (fixed per-round overhead \(String(format: "%.3f", fixed))s) —")
		for i in 0..<sizes.count {
			let adj = i == 0 ? 0.0 : adjusted[i - 1]
			print(String(format: "  n=%-5d total=%.3fs adjusted=%.3fs", sizes[i], times[i], adj))
		}
		print(String(format: "  doubling ratios: %@", ratios.map { String(format: "%.2f", $0) }.joined(separator: ", ")))
		print(String(format: "  fitted growth exponent (log2 scale) = %.2f  (linear≈1, quadratic≈2)", exponent))

		// Hard gates: no doubling ratio may exceed the polynomial bound, and
		// the fitted exponent must sit clearly below quadratic.
		for (i, r) in ratios.enumerated() {
			#expect(r < 6.0, "n=\(sizes[i + 1])→\(sizes[i + 2]) doubling ratio \(String(format: "%.2f", r)) exceeds the polynomial bound")
		}
		#expect(exponent < 2.0, "fitted log2 growth exponent \(String(format: "%.2f", exponent)) ≥ 2 ⇒ at least quadratic (and possibly exponential) scaling")

		// Correctness anchor: the largest measured pair must truly converge, so
		// the timings above reflect real reconciliation and not a silent no-op.
		let (a, b) = try self.makeScalePair(400, suffix: "verify")
		defer {
			try? TesseraDB.deleteEnvironment(base: base, environment: "aliceScaleverify", logLevel: .trace)
			try? TesseraDB.deleteEnvironment(base: base, environment: "bobScaleverify", logLevel: .trace)
		}
		try await self.syncOnce(alice: a, bob: b)
		try a.reindexAfterSync(logLevel: .error)
		try b.reindexAfterSync(logLevel: .error)
		#expect(a.eventCount == 2 + 2 * 400)
		#expect(b.eventCount == 2 + 2 * 400)
	}

	// MARK: - Verified index / driver hardening

	/// The verified index rejects value bytes that are not a decodeable valid
	/// signed event, or whose key does not match the event's own id — a hostile
	/// sync peer can never poison the store through the concord data phase.
	@Test func verifiedIndexRejectsInvalidValueAndAcceptsValid() throws {
		// No explicit abort needed: `Transaction`'s deinit aborts any
		// uncommitted transaction at scope exit.
		let trans = try Transaction<Write>(env: aliceDB.env)
		let db = try Database(env: aliceDB.syncEnvironment, name: "SignedEvents", flags: [], tx: trans)
		let cursor = try Cursor(db: db, tx: trans)
		let index = VerifiedConcordIndex(ConcordLMDBIndex<NOSTR_id, TesseraSignedEvent>(database: db, cursor: cursor))

		// Not decodeable as an event at all.
		let randomKeyBytes = try generateSecureRandomBytes(count: 32)
		let randomKey = NOSTR_id(RAW_decode: randomKeyBytes.withUnsafeBytes { $0 })!
		#expect(throws: ConcordSyncError.invalidValue(randomKey)) {
			try index.storeBytes(randomKey, ConcordOwnedBytes([0xDE, 0xAD, 0xBE, 0xEF]))
		}

		// A perfectly validly-encoded event stored under a key that does NOT
		// match its id must also be rejected.
		let valueBytes = ByteBuffer(rawObject: aliceNoteEvent)
		let rawValue = valueBytes.getBytes(at: 0, length: valueBytes.readableBytes)!
		#expect(throws: ConcordSyncError.invalidValue(randomKey)) {
			try index.storeBytes(randomKey, ConcordOwnedBytes(rawValue))
		}

		// The same bytes under the CORRECT key are accepted (no throw).
		try index.storeBytes(aliceNoteEvent.unsignedEvent.id, ConcordOwnedBytes(rawValue))
	}

	/// A transport that surfaces a malformed frame aborts the driver round and
	/// rolls the write transaction back: the store is left exactly as it was.
	@Test func driverRollsBackOnMalformedFrame() throws {
		struct BadFrameTransport: ConcordTransport {
			typealias Key = NOSTR_id
			typealias Value = TesseraSignedEvent
			func send(_ message: ConcordMessage<NOSTR_id, TesseraSignedEvent>) throws {}
			func receive() throws -> ConcordMessage<NOSTR_id, TesseraSignedEvent>? {
				throw ConcordWireError.badVersion(2)
			}
			func close() throws {}
		}
		let before = aliceDB.eventCount
		#expect(throws: ConcordWireError.self) {
			try runConcordRoundSync(env: aliceDB.syncEnvironment, role: .responder, transport: BadFrameTransport())
		}
		#expect(aliceDB.eventCount == before)
	}

	/// A regression guard for the read-then-flush concord model: while a round is
	/// mid-flight and parked on a stalled (offline / dropped-mid-sync) peer's
	/// `receive()`, the sync path holds only a READ transaction, so a concurrent
	/// WRITE must still acquire the LMDB writer immediately. Before the fix the
	/// round held a WRITE transaction across the network exchange and this write
	/// would block indefinitely.
	///
	/// Synchronous because `DispatchSemaphore.wait()` and the LMDB
	/// `Transaction`/`commit` calls are `@available(*, noasync)`; the round runs
	/// on a detached thread, exactly as `runConcordRoundAsync` does internally.
	@Test func roundDoesNotBlockWriter() throws {
		// A peer that blocks in `receive()` — the offline/dropped-mid-sync case.
		final class StalledPeer: ConcordTransport, @unchecked Sendable {
			typealias Key = NOSTR_id
			typealias Value = TesseraSignedEvent
			let entered = DispatchSemaphore(value: 0)   // receive() is now blocking
			let release = DispatchSemaphore(value: 0)   // unblock the round
			func send(_ message: ConcordMessage<NOSTR_id, TesseraSignedEvent>) throws {}
			func receive() throws -> ConcordMessage<NOSTR_id, TesseraSignedEvent>? {
				entered.signal()
				release.wait()
				return nil
			}
			func close() throws {}
		}

		let stalled = StalledPeer()
		let env = aliceDB.syncEnvironment

		// Run the round on its own thread; it parks inside receive(), holding
		// only a read transaction.
		let roundDone = DispatchSemaphore(value: 0)
		Thread.detachNewThread {
			defer { roundDone.signal() }
			do {
				try runConcordRoundSync(env: env, role: .initiator, transport: stalled)
			} catch {
				// The round aborts (prematureClose) when receive() returns nil.
			}
		}
		// Ensure the round unblocks even if the assertions/transaction below throw.
		defer { stalled.release.signal() }

		// Wait until the round is genuinely blocked in receive().
		stalled.entered.wait()

		// While the round holds only a READ transaction, a concurrent WRITE must
		// acquire the writer immediately. If it held a WRITE tx (pre-fix
		// behaviour), this would block indefinitely.
		let start = ContinuousClock.now
		let writeTx = try Transaction<Write>(env: env)
		try writeTx.commit()
		let elapsed = start.duration(to: .now)
		#expect(elapsed < .seconds(1), "writer was blocked by the in-flight round")

		// Unblock the round and wait for its thread to finish.
		stalled.release.signal()
		roundDone.wait()
	}
}
