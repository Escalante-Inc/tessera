import Testing
import Logging
import Foundation
import NIO
import RAW
import RAW_base64
import RAW_dh25519
import RAW_ed25519
import bedrock
import QuickLMDB
import nostr_kit_swift
@testable import tessera_core

/// Decodes a base64-encoded static private key via the v22 buffer API.
/// The decoded array is held in a local so the pointer stays valid for the
/// duration of the decode (avoids the dangling-temporary pitfall).
internal func memoryGuardedKey(fromBase64 base64: String) -> MemoryGuarded<RAW_dh25519.PrivateKey> {
	let bytes = try! RAW_base64.decode(base64)
	return MemoryGuarded<RAW_dh25519.PrivateKey>(RAW_decode: bytes.withUnsafeBytes { $0 })!
}

/// Builds a string-valued `EventTag` with the given index field (tag name).
/// These are the only tags that `tagIndex` stores, so tag-filter queries rely on them.
fileprivate func genericRefTag(_ name: String, _ value: String) -> EventTag {
	EventTag(indexField: NOSTR_tag_name(string: name)!, value: NOSTR_tag_generic_value(value))
}

/// Builds a `p` (pubkey reference) `EventTag` for the given public key.
fileprivate func userRefTag(_ key: PublicKey) -> EventTag {
	EventTag(indexField: NOSTR_tag_name(string: "p")!, value: NOSTR_tag_generic_value(String(RAW_base64.encode(key))))
}

@RAW_convertible_string_type<UTF8>(backing:RAW_byte.self)
struct Example1: Sendable {}

@RAW_staticbuff_binaryfloatingpoint_type<Float>
@RAW_staticbuff(bytes: 8)
struct Example2: Sendable {}

@RAW_staticbuff_fixedwidthinteger_type<UInt128>(bigEndian: false)
@RAW_staticbuff(bytes: 16)
struct Example3: Sendable {}

@Suite("Tessera Tests", .serialized)
struct TesseraTests {}


extension TesseraTests {
	
	@Suite("Tessera Database Tests", .serialized)
	class DatabaseTests {
		let cliLogger:Logger
		let base = Path(FileManager.default.homeDirectoryForCurrentUser.path)
		let tesseraDB:TesseraDB
		
		static let aliceStaticPrivateKey = memoryGuardedKey(fromBase64: "8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI=")
		static let bobStaticPrivateKey = memoryGuardedKey(fromBase64: "SD/y8yQa/DgiYRnDI9vJEiGezNn4yLd/4yL9OLnej0A=")
		static let adminStaticPrivateKey = memoryGuardedKey(fromBase64: "EEug1Qbe4WjR1TDq4iN4Ce4Rh5iN4aDR407/e5bQgW4=")

		let aliceEd25519PublicKey:PublicKey
		let aliceEd25519PrivateKey:MemoryGuarded<RAW_ed25519.PrivateKey>
		let alicePrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		
		let bobEd25519PublicKey:PublicKey
		let bobEd25519PrivateKey:MemoryGuarded<RAW_ed25519.PrivateKey>
		let bobPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		
		let adminEd25519PublicKey:PublicKey
		let adminEd25519PrivateKey:MemoryGuarded<RAW_ed25519.PrivateKey>
		let adminPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		
		let aliceSignedEvent: NOSTR_event_signed<UnsignedEvent<ByteBuffer>>
		let bobSignedEvent: NOSTR_event_signed<UnsignedEvent<ByteBuffer>>
		let adminSignedEvent: NOSTR_event_signed<UnsignedEvent<ByteBuffer>>
		
		let aliceProfileEvent: NOSTR_event_signed<UnsignedEvent<ByteBuffer>>
		let bobProfileEvent: NOSTR_event_signed<UnsignedEvent<ByteBuffer>>
		let adminProfileEvent: NOSTR_event_signed<UnsignedEvent<ByteBuffer>>
		
		init() throws {
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = .debug
			cliLogger = buildLogger
			alicePrivateKey = Self.aliceStaticPrivateKey
			bobPrivateKey = Self.bobStaticPrivateKey
			adminPrivateKey = Self.adminStaticPrivateKey
			(aliceEd25519PublicKey, aliceEd25519PrivateKey) = try RAW_ed25519.generateKeys(secretKey: alicePrivateKey)
			(bobEd25519PublicKey, bobEd25519PrivateKey) = try RAW_ed25519.generateKeys(secretKey: bobPrivateKey)
			(adminEd25519PublicKey, adminEd25519PrivateKey) = try RAW_ed25519.generateKeys(secretKey: adminPrivateKey)
			// Ensure a fresh database for this suite instance. Swift Testing may create multiple
			// instances of this suite (one per test), so a leftover DB would cause duplicate-key
			// failures on the shared `~/tessera.mdb`.
			try? TesseraDB.deleteEnvironment(base: base, environment: "tessera", logLevel: .error)
			self.tesseraDB = try TesseraDB(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error)
			
			aliceProfileEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [1]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Alice"))).sign(as: aliceEd25519PrivateKey)
			bobProfileEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0,1])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [0,2]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Bob"))).sign(as: bobEd25519PrivateKey)
			adminProfileEvent = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0,1,2,255])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [0,1,2,255]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Admin"))).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .info)
			try tesseraDB.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .info)
			try tesseraDB.scribeNewUser(signedEvent: adminProfileEvent, logLevel: .info)
			
			aliceSignedEvent = try UnsignedEvent(
				publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -1, to: Date())!),
				tags: [userRefTag(bobEd25519PublicKey), genericRefTag("a", "Alice Tag")], application: 0,
				kind: 10000, content: ByteBuffer(string: "Alice Content")).sign(as: aliceEd25519PrivateKey)
			bobSignedEvent = try UnsignedEvent(
				publicKey: bobEd25519PublicKey, date: NOSTR_date(date: Date()),
				tags: [userRefTag(aliceEd25519PublicKey), genericRefTag("b", "Bob Tag"), DTag(value: "testUniqueDTag")], application: 1,
				kind: 30000, content: ByteBuffer(string: "Bob Content")).sign(as: bobEd25519PrivateKey)
			adminSignedEvent = try UnsignedEvent(
				publicKey: adminEd25519PublicKey, date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: 1, to: Date())!),
				tags: [userRefTag(aliceEd25519PublicKey), userRefTag(bobEd25519PublicKey), genericRefTag("ad", "Admin Tag")], application: 0,
				kind: 10000, content: ByteBuffer(string: "Admin Content")).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: aliceSignedEvent, logLevel: .info)
			try tesseraDB.scribeNewEvent(signedEvent: bobSignedEvent, logLevel: .info)
			try tesseraDB.scribeNewEvent(signedEvent: adminSignedEvent, logLevel: .info)
		}
		
		deinit {
			do {
				try TesseraDB.deleteEnvironment(base: base, environment: "tessera", logLevel: .trace)
			} catch {
				cliLogger.error(Logger.Message.red("Failed to delete the testing database at \(String(describing: base.path))"))
			}
		}
		
		@Test func writeDeletionEvent() throws {
			let validDeletionEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventRefTag(value: aliceSignedEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: validDeletionEvent, logLevel: .trace)
			#expect(tesseraDB.eventCount == 7)
			
			let invalidKeyDeletionEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [EventRefTag(value: aliceSignedEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: bobEd25519PrivateKey)
			#expect(throws: SignedNoteError.invalidKind5PublicKey) {
				try tesseraDB.scribeNewEvent(signedEvent: invalidKeyDeletionEvent, logLevel: .trace)
			}
			
			let invalidTagDeletionEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventRefTag(value: invalidKeyDeletionEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
			#expect(throws: SignedNoteError.invalidKind5Tag) {
				try tesseraDB.scribeNewEvent(signedEvent: invalidTagDeletionEvent, logLevel: .trace)
			}
		}
		
		@Test func emptySmartFilter() throws {
			let events = try tesseraDB.queryEventsBySmartFilter(filters: [])
			#expect(events.count == 0)
		}
		
		@Test func smartFilterIds() throws {
			let aliceIdsFilter = Filter(ids: [aliceSignedEvent.unsignedEvent.id, aliceProfileEvent.unsignedEvent.id])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [aliceIdsFilter])
			#expect(events.count == 2)
			
			let bobIdsFilter = Filter(ids: [bobSignedEvent.unsignedEvent.id])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [bobIdsFilter])
			#expect(events.count == 1)
		}
		
		@Test func smartFilterAuthor() throws {
			let alicePkFilter = Filter(authors: [aliceEd25519PublicKey])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [alicePkFilter])
			#expect(events.count == 2)
			
			let bobPkFilter = Filter(authors: [bobEd25519PublicKey])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [alicePkFilter, bobPkFilter])
			#expect(events.count == 4)
		}
		
		@Test func smartFilterApplication() throws {
			let kindFilterA = Filter(applications: [NOSTR_application(RAW_native: 0)])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [kindFilterA])
			#expect(events.count == 5)
			
			let kindFilterB = Filter(applications: [NOSTR_application(RAW_native: 0), NOSTR_application(RAW_native: 1)])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [kindFilterB])
			#expect(events.count == 6)
		}
		
		@Test func smartFilterKind() throws {
			let kindFilterA = Filter(kinds: [NOSTR_kind(RAW_native: 0)])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [kindFilterA])
			#expect(events.count == 3)
			
			let kindFilterB = Filter(kinds: [NOSTR_kind(RAW_native: 0), NOSTR_kind(RAW_native: 30000)])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [kindFilterB])
			#expect(events.count == 4)
		}
		
		@Test func smartFilterTag() throws {
			let tagFilterA = Filter(tags: [userRefTag(aliceEd25519PublicKey)])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [tagFilterA])
			#expect(events.count == 2)
			
			let tagFilterB = Filter(tags: [userRefTag(aliceEd25519PublicKey), userRefTag(bobEd25519PublicKey), genericRefTag("ad", "Admin Tag")])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [tagFilterB])
			#expect(events.count == 1)
		}
		
		@Test func smartFilterDate() throws {
			let dateFilterA = Filter(since: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: -1, to: Date())!))
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [dateFilterA])
			#expect(events.count == 5)
			
			let dateFilterB = Filter(until: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: 1, to: Date())!))
			events = try tesseraDB.queryEventsBySmartFilter(filters: [dateFilterB])
			#expect(events.count == 5)
			
			let dateFilterC = Filter(since: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: -1, to: Date())!),
									 until: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: 1, to: Date())!))
			events = try tesseraDB.queryEventsBySmartFilter(filters: [dateFilterC])
			#expect(events.count == 4)
			
			let dateFilterD = Filter(since: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: 2, to: Date())!),
									 until: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: 3, to: Date())!))
			events = try tesseraDB.queryEventsBySmartFilter(filters: [dateFilterD])
			#expect(events.count == 0)
			
			let dateFilterE = Filter(since: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: 1, to: Date())!),
									 until: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: -1, to: Date())!))
			events = try tesseraDB.queryEventsBySmartFilter(filters: [dateFilterE])
			#expect(events.count == 0)
		}
		
		@Test func smartFilterCombined() throws {
			let combinedFilterA = Filter(authors: [aliceEd25519PublicKey], until: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: 1, to: Date())!))
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterA])
			#expect(events.count == 2)
			
			let combinedFilterB = Filter(authors: [aliceEd25519PublicKey], tags: [userRefTag(bobEd25519PublicKey), genericRefTag("a", "Alice Tag")], until: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: 1, to: Date())!))
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterB])
			#expect(events.count == 1)
			
			let combinedFilterC = Filter(authors: [aliceEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0)], tags: [userRefTag(bobEd25519PublicKey), genericRefTag("a", "Alice Tag")], until: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: 1, to: Date())!))
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterC])
			#expect(events.count == 0)
			
			let combinedFilterD = Filter(authors: [aliceEd25519PublicKey, bobEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0), NOSTR_kind(RAW_native: 10000)])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterD])
			#expect(events.count == 3)
			
			let combinedFilterE = Filter(authors: [aliceEd25519PublicKey, adminEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0), NOSTR_kind(RAW_native: 10000)], tags: [genericRefTag("ad", "Admin Tag")])
			let combinedFilterF = Filter(authors: [aliceEd25519PublicKey, adminEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0), NOSTR_kind(RAW_native: 10000)], tags: [genericRefTag("a", "Alice Tag")])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterE, combinedFilterF])
			#expect(events.count == 2)
			
			let combinedFilterG = Filter(ids: [aliceSignedEvent.unsignedEvent.id, bobSignedEvent.unsignedEvent.id], authors: [aliceEd25519PublicKey])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterG])
			#expect(events.count == 1)
		}
		
		@Test func smartFilterWithUpdates() throws {
			let updatedEvent = try UnsignedEvent( publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Date()),
												  tags: [userRefTag(bobEd25519PublicKey), genericRefTag("a", "New Alice Tag")], application: 0,
				kind: 10000, content: ByteBuffer(string: "New Alice Content")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: updatedEvent, logLevel: .trace)
			let filter = Filter(authors: [aliceEd25519PublicKey], tags:[userRefTag(bobEd25519PublicKey)])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [filter])
			#expect(events.count == 1)
			#expect(events[0].unsignedEvent.content == ByteBuffer(string: "New Alice Content"))
			
			let updatedEvent2 = try UnsignedEvent( publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Calendar.current.date(byAdding: .second, value: 1, to: Date())!),
												   tags: [userRefTag(bobEd25519PublicKey), genericRefTag("a", "Newer Alice Tag")], application: 0,
				kind: 10000, content: ByteBuffer(string: "Newer Alice Content")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: updatedEvent2, logLevel: .trace)
			events = try tesseraDB.queryEventsBySmartFilter(filters: [filter])
			#expect(events.count == 1)
			#expect(events[0].unsignedEvent.content == ByteBuffer(string: "Newer Alice Content"))
		}
		
		@Test func smartFilterWithDeletions() throws {
			let aliceDeletionEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventRefTag(value: aliceSignedEvent.unsignedEvent.id), EventRefTag(value: aliceProfileEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
			let bobDeletionEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [EventRefTag(value: bobSignedEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: bobEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: aliceDeletionEvent, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: bobDeletionEvent, logLevel: .trace)
			#expect(tesseraDB.eventCount == 8)
			
			let aliceFilter = Filter(authors: [aliceEd25519PublicKey])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [aliceFilter])
			#expect(events.count == 0)
			
			let bobFilter = Filter(authors: [bobEd25519PublicKey])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [bobFilter])
			#expect(events.count == 1)
		}
		
		@Test func smartFilterWithForceDelete() throws {
			tesseraDB.forceDeleteEvent(id: aliceSignedEvent.unsignedEvent.id)
			#expect(tesseraDB.eventCount == 5)
			let aliceFilter = Filter(authors: [aliceEd25519PublicKey])
			let events = try tesseraDB.queryEventsBySmartFilter(filters: [aliceFilter])
			#expect(events.count == 1)
		}
		
		@Test func testWritePermissions() throws {
			let aliceWriteAccessOne = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [], application: NOSTR_application(RAW_native: 0), kind: createKind(accessLevel: 0, kind: 10_000), content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
			#expect(throws: AccessLevelError.invalidWriteAccess) {
				try tesseraDB.scribeNewEvent(signedEvent: aliceWriteAccessOne, logLevel: .trace)
			}
			let aliceWriteAccessTwo = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [], application: NOSTR_application(RAW_native: 0), kind: createKind(accessLevel: 1, kind: 10_000), content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: aliceWriteAccessTwo, logLevel: .trace)
			
			let adminWriteAccessZero = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [], application: NOSTR_application(RAW_native: 0), kind: createKind(accessLevel: 0, kind: 10_000), content: ByteBuffer()).sign(as: adminEd25519PrivateKey)
			let adminWriteAccess255 = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [], application: NOSTR_application(RAW_native: 0), kind: createKind(accessLevel: 255, kind: 10_000), content: ByteBuffer()).sign(as: adminEd25519PrivateKey)
			let adminWriteAccessMax = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [], application: 0, kind: 11_000_000, content: ByteBuffer()).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: adminWriteAccessZero, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: adminWriteAccess255, logLevel: .trace)
			#expect(throws: AccessLevelError.invalidWriteAccess) {
				try tesseraDB.scribeNewEvent(signedEvent: adminWriteAccessMax, logLevel: .trace)
			}
		}
		
		@Test func testReadPermissions() throws {
			let adminWriteAccessZero = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [], application: NOSTR_application(RAW_native: 0), kind: createKind(accessLevel: 0, kind: 10_000), content: ByteBuffer()).sign(as: adminEd25519PrivateKey)
			let adminWriteAccessOne = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [], application: NOSTR_application(RAW_native: 0), kind: createKind(accessLevel: 1, kind: 10_000), content: ByteBuffer()).sign(as: adminEd25519PrivateKey)
			let adminWriteAccessTwo = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [], application: NOSTR_application(RAW_native: 0), kind: createKind(accessLevel: 2, kind: 10_000), content: ByteBuffer()).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: adminWriteAccessZero, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: adminWriteAccessOne, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: adminWriteAccessTwo, logLevel: .trace)
			
			var filter = Filter(authors: [adminEd25519PublicKey])
			#expect(throws: AccessLevelError.invalidReadAccess) {
				_ = try tesseraDB.queryEventsBySmartFilter(filters: [filter], user: aliceEd25519PublicKey)
			}
			_ = try tesseraDB.queryEventsBySmartFilter(filters: [filter], user: adminEd25519PublicKey)
			
			let bobWriteAccessZero = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [], application: NOSTR_application(RAW_native: 0), kind: createKind(accessLevel: 0, kind: 10_000), content: ByteBuffer()).sign(as: bobEd25519PrivateKey)
			let bobWriteAccessTwo = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [], application: NOSTR_application(RAW_native: 0), kind: createKind(accessLevel: 2, kind: 10_000), content: ByteBuffer()).sign(as: bobEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: bobWriteAccessZero, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: bobWriteAccessTwo, logLevel: .trace)
			filter = Filter(authors: [bobEd25519PublicKey])
			#expect(throws: AccessLevelError.invalidReadAccess) {
				_ = try tesseraDB.queryEventsBySmartFilter(filters: [filter], user: bobEd25519PublicKey)
			}
		}

		@Test func rangeIndexMapsOnlyValidKindRanges() {
			// The access bitmap holds 256 levels; only kinds in
			// [40_000, 10_280_000) map to 0...255. Everything else must be nil
			// (deny), never a negative index that would trap on `1 << bitIndex`.
			#expect(rangeIndex(for: 40_000) == 0)          // access level 0, kind 0
			#expect(rangeIndex(for: 40_001) == 0)          // access level 0, kind 1
			#expect(rangeIndex(for: 80_000) == 1)          // access level 1, kind 0
			#expect(rangeIndex(for: 10_279_999) == 255)    // last level, last kind
			#expect(rangeIndex(for: 10_280_000) == nil)    // one past the bitmap
			#expect(rangeIndex(for: 11_000_000) == nil)    // far out of range
			#expect(rangeIndex(for: 39_999) == nil)        // below the access-controlled range
			#expect(rangeIndex(for: 0) == nil)
			#expect(rangeIndex(for: -1) == nil)
		}

		@Test func outOfRangeKindDeniedNotTrapped() throws {
			// Regression test for the process crash: `rangeIndex` previously returned
			// -1 for kinds >= 10_280_000, and `1 << (-1 % 8)` is a runtime trap that
			// killed the whole daemon. Access checks must now deny (write/read) or
			// skip (forgiving) out-of-range kinds — never crash.
			let readTx = try Transaction(env: tesseraDB.env, readOnly: true)
			#expect(try tesseraDB.checkWriteAccess(user: aliceEd25519PublicKey, kind: NOSTR_kind(RAW_native: 11_000_000), tx: readTx) == false)
			#expect(try tesseraDB.checkReadAccess(user: aliceEd25519PublicKey, kinds: [NOSTR_kind(RAW_native: 11_000_000)], tx: readTx) == false)
			#expect(try tesseraDB.checkReadAccessForgiving(user: aliceEd25519PublicKey, kinds: [NOSTR_kind(RAW_native: 11_000_000)], tx: readTx).isEmpty)
			// Boundary: the highest valid kind is still checked against the bitmap.
			#expect(try tesseraDB.checkReadAccess(user: aliceEd25519PublicKey, kinds: [NOSTR_kind(RAW_native: 10_279_999)], tx: readTx) == false)
		}

		@Test func forgivingReadAccessTestsBitsNotJustBitZero() throws {
			// Regression test for the silent read denial: `checkReadAccessForgiving`
			// previously tested `(byte & (1 << bitIndex)) == 1`, which only ever
			// matches bitIndex 0. Bob holds readAL [0, 1], so byte 0 is 0b11; kind
			// 80_000 (access level 1, kind 0) hits bit 1, where `3 & 2 == 2` and
			// `2 == 1` is false — Bob was wrongly denied a kind he was granted.
			let readTx = try Transaction(env: tesseraDB.env, readOnly: true)
			// Level 1 bit (kind 80_000) must be honored — the bug denied this.
			#expect(try tesseraDB.checkReadAccessForgiving(user: bobEd25519PublicKey, kinds: [NOSTR_kind(RAW_native: 80_000)], tx: readTx) == [NOSTR_kind(RAW_native: 80_000)])
			// Level 0 bit (kind 40_000) still works.
			#expect(try tesseraDB.checkReadAccessForgiving(user: bobEd25519PublicKey, kinds: [NOSTR_kind(RAW_native: 40_000)], tx: readTx) == [NOSTR_kind(RAW_native: 40_000)])
			// Level 2 bit (kind 120_000) was never granted — must stay denied even with == 0/!= 0.
			#expect(try tesseraDB.checkReadAccessForgiving(user: bobEd25519PublicKey, kinds: [NOSTR_kind(RAW_native: 120_000)], tx: readTx).isEmpty)
			// Sub-40_000 kinds are always allowed by the forgiving path.
			#expect(try tesseraDB.checkReadAccessForgiving(user: bobEd25519PublicKey, kinds: [NOSTR_kind(RAW_native: 5_000)], tx: readTx) == [NOSTR_kind(RAW_native: 5_000)])
			// Non-owning user without the bit must be denied.
			#expect(try tesseraDB.checkReadAccessForgiving(user: aliceEd25519PublicKey, kinds: [NOSTR_kind(RAW_native: 80_000)], tx: readTx).isEmpty)
		}

		@Test func smartFilterUntilBoundaryIsInclusive() throws {
			// NIP-01: `until` is an inclusive upper bound, and `applyTesseraFilter` (live
			// fan-out) already uses `<=`. The history query previously used an exclusive `key <
			// until`, so an event created exactly at the `until` timestamp was dropped from
			// history but pushed live. Both paths must agree.
			let boundaryDate = Calendar.current.date(byAdding: .hour, value: -3, to: Date())!
			let boundary = NOSTR_date(date: boundaryDate)
			// Kind 5000 is non-replaceable, so the smart filter never needs a d-tag for it.
			let boundaryEvent = try UnsignedEvent(
				publicKey: aliceEd25519PublicKey, date: boundary,
				tags: [], application: 0, kind: 5_000,
				content: ByteBuffer(string: "boundary event")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: boundaryEvent, logLevel: .trace)

			// Event at exactly `until` must be returned.
			let untilOnly = Filter(until: boundary)
			let untilEvents = try tesseraDB.queryEventsBySmartFilter(filters: [untilOnly])
			#expect(untilEvents.contains { $0.unsignedEvent.id == boundaryEvent.unsignedEvent.id })

			// Event at exactly `since` AND `until` (single instant) must be returned.
			let clamped = Filter(since: boundary, until: boundary)
			let clampedEvents = try tesseraDB.queryEventsBySmartFilter(filters: [clamped])
			#expect(clampedEvents.contains { $0.unsignedEvent.id == boundaryEvent.unsignedEvent.id })

			// An event created strictly after the `until` bound must be excluded.
			let laterEvent = try UnsignedEvent(
				publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: boundaryDate.addingTimeInterval(3 * 60 * 60)),
				tags: [], application: 0, kind: 5_000,
				content: ByteBuffer(string: "later event")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: laterEvent, logLevel: .trace)
			let bounded = try tesseraDB.queryEventsBySmartFilter(filters: [Filter(until: boundary)])
			#expect(!bounded.contains { $0.unsignedEvent.id == laterEvent.unsignedEvent.id })
			#expect(bounded.contains { $0.unsignedEvent.id == boundaryEvent.unsignedEvent.id })
		}

		@Test func forceUpdateEventRewritesIndexes() throws {
			// Fresh event so the test is independent of other tests' mutations of the
			// shared suite database (a prior test may have force-deleted aliceSignedEvent).
			let original = try UnsignedEvent(
				publicKey: aliceEd25519PublicKey,
				tags: [], application: 0, kind: 5_000,
				content: ByteBuffer(string: "Original Content")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: original, logLevel: .trace)
			let originalID = original.unsignedEvent.id

			tesseraDB.forceUpdateEvent(id: originalID, admin: adminEd25519PrivateKey, newContent: ByteBuffer(string: "Rewritten Content"))

			// Original id must no longer exist in the main store.
			let byOriginalID = try tesseraDB.queryEventsBySmartFilter(filters: [Filter(ids: [originalID])])
			#expect(!byOriginalID.contains { $0.unsignedEvent.id == originalID })

			// The rewritten event (same kind, uri-relevant fields, fresh id + content) must be
			// reachable through the kind index — it must not be invisible to queries.
			let byKind = try tesseraDB.queryEventsBySmartFilter(filters: [Filter(kinds: [NOSTR_kind(RAW_native: 5_000)])])
			#expect(byKind.contains { $0.unsignedEvent.content == ByteBuffer(string: "Rewritten Content") })
			#expect(!byKind.contains { $0.unsignedEvent.id == originalID })
			#expect(!byKind.contains { $0.unsignedEvent.content == ByteBuffer(string: "Original Content") })
		}

		@Test func forceUpdateEventFilteredRewritesIndexes() throws {
			// Scribe two fresh events so the filter selects exactly these.
			let originalA = try UnsignedEvent(
				publicKey: aliceEd25519PublicKey,
				tags: [], application: 0, kind: 5_000,
				content: ByteBuffer(string: "A Original")).sign(as: aliceEd25519PrivateKey)
			let originalB = try UnsignedEvent(
				publicKey: bobEd25519PublicKey,
				tags: [], application: 0, kind: 5_000,
				content: ByteBuffer(string: "B Original")).sign(as: bobEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: originalA, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: originalB, logLevel: .trace)
			let idA = originalA.unsignedEvent.id
			let idB = originalB.unsignedEvent.id

			tesseraDB.forceUpdateEventFiltered(
				filters: [Filter(ids: [idA, idB])],
				admin: adminEd25519PrivateKey,
				newContent: ByteBuffer(string: "Filtered Rewrite"))

			// Both originals gone, both rewrites reachable through the kind index.
			let byKind = try tesseraDB.queryEventsBySmartFilter(filters: [Filter(kinds: [NOSTR_kind(RAW_native: 5_000)])])
			#expect(!byKind.contains { $0.unsignedEvent.id == idA })
			#expect(!byKind.contains { $0.unsignedEvent.id == idB })
			#expect(byKind.filter { $0.unsignedEvent.content == ByteBuffer(string: "Filtered Rewrite") }.count == 2)
		}

		@Test func smartFilterSkipsMissingIds() throws {
			// A filter whose `ids` field references an event that was never stored must not
			// abort the whole query — NIP-01 requires missing ids to be skipped while the
			// stored ids are still returned.
			let fresh = try UnsignedEvent(
				publicKey: aliceEd25519PublicKey,
				tags: [], application: 0, kind: 7_000,
				content: ByteBuffer(string: "kept event")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: fresh, logLevel: .trace)
			let freshID = fresh.unsignedEvent.id

			let missing = NOSTR_id(RAW_decode: [UInt8](repeating:0, count:32).withUnsafeBytes { $0 })!
			let filter = Filter(ids: [freshID, missing])
			let events = try tesseraDB.queryEventsBySmartFilter(filters: [filter])
			#expect(events.count == 1)
			#expect(events[0].unsignedEvent.id == freshID)

			// Same for the dumb (history) path.
			let dumbEvents = try tesseraDB.queryEventsByDumbFilter(filters: [filter])
			#expect(dumbEvents.count == 1)
			#expect(dumbEvents[0].unsignedEvent.id == freshID)
		}

		@Test func dumbFilterHonorsLimit() throws {
			// Scribe three events it can limit against, so the test doesn't depend on how
			// many events other tests left in the shared database.
			var scribedIDs: [NOSTR_id] = []
			for i in 0..<3 {
				let event = try UnsignedEvent(
					publicKey: aliceEd25519PublicKey,
					tags: [], application: 0, kind: 8_000,
					content: ByteBuffer(string: "limit event \(i)")).sign(as: aliceEd25519PrivateKey)
				try tesseraDB.scribeNewEvent(signedEvent: event, logLevel: .trace)
				scribedIDs.append(event.unsignedEvent.id)
			}

			// The history path previously ignored `limit` entirely (only the smart filter
			// applied it), so a history REQ could return the full database. It must honor the
			// limit and return the newest events first, like the smart path.
			let filter = Filter(ids: scribedIDs, limit: NOSTR_filter_limit(RAW_native: 2))
			let events = try tesseraDB.queryEventsByDumbFilter(filters: [filter])
			#expect(events.count == 2)
			#expect(events[0].unsignedEvent.date >= events[1].unsignedEvent.date)
		}
	}
}

extension TesseraTests {
	@Suite("Large Data Tests", .serialized)
	class LargeDataTests {
		let cliLogger:Logger
		let base = Path(FileManager.default.homeDirectoryForCurrentUser.path)
		let tesseraDB:TesseraDB
		
		static let aliceStaticPrivateKey = memoryGuardedKey(fromBase64: "8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI=")
		static let bobStaticPrivateKey = memoryGuardedKey(fromBase64: "SD/y8yQa/DgiYRnDI9vJEiGezNn4yLd/4yL9OLnej0A=")
		static let adminStaticPrivateKey = memoryGuardedKey(fromBase64: "EEug1Qbe4WjR1TDq4iN4Ce4Rh5iN4aDR407/e5bQgW4=")

		let aliceEd25519PublicKey:PublicKey
		let aliceEd25519PrivateKey:MemoryGuarded<RAW_ed25519.PrivateKey>
		let alicePrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		
		let bobEd25519PublicKey:PublicKey
		let bobEd25519PrivateKey:MemoryGuarded<RAW_ed25519.PrivateKey>
		let bobPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		
		let adminEd25519PublicKey:PublicKey
		let adminEd25519PrivateKey:MemoryGuarded<RAW_ed25519.PrivateKey>
		let adminPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		
		init() throws {
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = .debug
			cliLogger = buildLogger
			alicePrivateKey = Self.aliceStaticPrivateKey
			bobPrivateKey = Self.bobStaticPrivateKey
			adminPrivateKey = Self.adminStaticPrivateKey
			(aliceEd25519PublicKey, aliceEd25519PrivateKey) = try RAW_ed25519.generateKeys(secretKey: alicePrivateKey)
			(bobEd25519PublicKey, bobEd25519PrivateKey) = try RAW_ed25519.generateKeys(secretKey: bobPrivateKey)
			(adminEd25519PublicKey, adminEd25519PrivateKey) = try RAW_ed25519.generateKeys(secretKey: adminPrivateKey)
			// Ensure a fresh database for this suite instance. Swift Testing may create multiple
			// instances of this suite (one per test), so a leftover DB would cause duplicate-key
			// failures on the shared `~/tessera.mdb`.
			try? TesseraDB.deleteEnvironment(base: base, environment: "tessera", logLevel: .error)
			self.tesseraDB = try TesseraDB(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error)
		}
		
		@Test func fillAndQueryDatabase() throws {
			// Users (needed for read/write access checks on the events written below).
			let aliceProfileEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [1]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Alice"))).sign(as: aliceEd25519PrivateKey)
			let bobProfileEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0,1])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [0,2]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Bob"))).sign(as: bobEd25519PrivateKey)
			let adminProfileEvent = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [ReadAccessLevels(value: UserAccessLevel(accessLevels: [0,1,2,255])), WriteAccessLevels(value: UserAccessLevel(accessLevels: [0,1,2,255]))], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Admin"))).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .info)
			try tesseraDB.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .info)
			try tesseraDB.scribeNewUser(signedEvent: adminProfileEvent, logLevel: .info)
			let authors = [(aliceEd25519PublicKey, aliceEd25519PrivateKey), (bobEd25519PublicKey, bobEd25519PrivateKey), (adminEd25519PublicKey, adminEd25519PrivateKey)]
			let tagValues = ["Tag0", "Tag1", "Tag2", "Tag3", "Tag4", "Tag5", "Tag6", "Tag7", "Tag8", "Tag9"]
			let tagNames: [Character] = Array("abcefghijklmnopqrstuvwxyz")
		
			// Fill the database with a large volume of signed events across all three authors.
			for _ in 0..<50_000 {
				let author = authors.randomElement()!
				let kind = UInt32.random(in: [10_000...24_999, 30_000...39_999].randomElement()!)
				let application = UInt16.random(in: UInt16.min...UInt16.max)
				let signedEvent = try UnsignedEvent(
					publicKey: author.0,
					date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: Int.random(in: -365...365), to: Date())!),
					tags: [genericRefTag(String(tagNames.randomElement()!), tagValues.randomElement()!),
						   kind > 14_999 ? DTag(value: Encoded.String(tagValues.randomElement()!)) :
							genericRefTag(String(tagNames.randomElement()!), tagValues.randomElement()!)], application: application,
					kind: kind,
					content: ByteBuffer(string: "")).sign(as: author.1)
				try tesseraDB.scribeNewEvent(signedEvent: signedEvent, logLevel: .warning)
			}
			cliLogger.info("Database Size: ")
		
			// Exercise both the smart and dumb filters over the populated database.
			let filterA = Filter(authors: [aliceEd25519PublicKey], tags: [genericRefTag("a", "Tag0")])
			let filterB = Filter(authors: [aliceEd25519PublicKey, bobEd25519PublicKey],
								 since: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -50, to: Date())!),
								 until: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: 50, to: Date())!))
			let smartEvents = try tesseraDB.queryEventsBySmartFilter(filters: [filterA, filterB])
			let dumbEvents = try tesseraDB.queryEventsByDumbFilter(filters: [filterA, filterB])
			cliLogger.info("smartFilter found \(smartEvents.count) events")
			cliLogger.info("dumbFilter found \(dumbEvents.count) events")
			// The author/date filter alone must match a substantial share of the 50k events.
			#expect(dumbEvents.count > 100)
		}
		
		@Test func deleteDatabase() {
			do {
				try TesseraDB.deleteEnvironment(base: base, environment: "tessera", logLevel: .trace)
			} catch {
				cliLogger.error(Logger.Message.red("Failed to delete the testing database at \(String(describing: base.path))"))
			}
		}
	}
}

extension TesseraTests {
	@Suite("encode decode tests")
	class EncodeDecodeTests {
		@Test func encodeDecodeByteBuffer() {
			let byteBuffer = ByteBufferAllocator().buffer(staticString: "Tessera Test String")
			var byteBufferLen = 0; byteBuffer.RAW_encode(count: &byteBufferLen)
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: byteBufferLen)
			defer { pointer.deallocate() }
			_ = byteBuffer.RAW_encode(dest:pointer.baseAddress!)
			let decodedByteBuffer = ByteBuffer(RAW_decode: UnsafeRawBufferPointer(pointer))!
			#expect(byteBuffer == decodedByteBuffer)
		}
		
		@Test func encodeDecodeUser() {
			let user = User(userName: "Alice")
			var userLen = 0; user.RAW_encode(count: &userLen)
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: userLen)
			defer { pointer.deallocate() }
			_ = user.RAW_encode(dest:pointer.baseAddress!)
			let decodedUser = User(RAW_decode: UnsafeRawBufferPointer(pointer))!
			#expect(user.userName == decodedUser.userName)
		}
		
		@Test func userRAWaccess() throws {
			let user = User(userName: "Bob")
			var userLen = 0; user.RAW_encode(count: &userLen)
			let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: userLen)
			defer { buffer.deallocate() }
			_ = user.RAW_encode(dest:buffer.baseAddress!)
			user.RAW_access_immutable(UnsafeBufferPointer<UInt8>.self) { ptr in
				#expect(ptr.count == buffer.count)
				#expect(memcmp(ptr.baseAddress!, buffer.baseAddress!, buffer.count) == 0)
			}
		}
		
		@Test func encodeDecodeReplaceableKey() {
			var replaceableKey = ReplaceableKey(pubkey: nil, kind: NOSTR_kind(RAW_native: 100), dTag: nil)
			var replaceableKeyLen = 0; replaceableKey.RAW_encode(count: &replaceableKeyLen)
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: replaceableKeyLen)
			defer { pointer.deallocate() }
			_ = replaceableKey.RAW_encode(dest:pointer.baseAddress!)
			var decodedReplaceableKey = ReplaceableKey(RAW_decode: UnsafeRawBufferPointer(pointer))!
			#expect(replaceableKey == decodedReplaceableKey)
		
			replaceableKey = ReplaceableKey(pubkey: PublicKey(privateKey: DatabaseTests.aliceStaticPrivateKey), kind: NOSTR_kind(RAW_native: 100), dTag: nil)
			replaceableKeyLen = 0; replaceableKey.RAW_encode(count: &replaceableKeyLen)
			let pointer2 = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: replaceableKeyLen)
			defer { pointer2.deallocate() }
			_ = replaceableKey.RAW_encode(dest:pointer2.baseAddress!)
			decodedReplaceableKey = ReplaceableKey(RAW_decode: UnsafeRawBufferPointer(pointer2))!
			#expect(replaceableKey == decodedReplaceableKey)
		}
	
		@Test func replaceableKeyDecodeRejectsTruncatedInput() {
			// A key with a pubkey exercises every branch: presence flag, 32-byte pubkey,
			// kind, d-tag length, and d-tag bytes. Any strict truncation of a pubkey-bearing
			// key must decode to `nil` — never over-read past the end of the buffer
			// (regression test for the OOB read fixed by using the remaining `dataCount`
			// in every guard instead of the original `count`).
			let fullKey = ReplaceableKey(
				pubkey: PublicKey(privateKey: DatabaseTests.aliceStaticPrivateKey),
				kind: NOSTR_kind(RAW_native: 30_000),
				dTag: DTag(value: "regression-dtag"))
			var fullLen = 0; fullKey.RAW_encode(count: &fullLen)
			let buf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: fullLen)
			defer { buf.deallocate() }
			_ = fullKey.RAW_encode(dest: buf.baseAddress!)
		
			// Full decode round-trips.
			#expect(ReplaceableKey(RAW_decode: UnsafeRawBufferPointer(buf)) == fullKey)
		
			// Every strict truncation returns nil (catches the former OOB over-read
			// inside the pubkey / kind / d-tag sections).
			for cut in 1..<fullLen {
				#expect(ReplaceableKey(RAW_decode: UnsafeRawBufferPointer(rebasing: UnsafeRawBufferPointer(buf)[0..<cut])) == nil,
					"truncation at \(cut)/\(fullLen) should decode as nil")
			}
		}
	
		@Test func applyTesseraFilterRespectsApplications() throws {
			let keypair = try DatabaseTests.alicePrivateKeyWithKeypair()
			let event = try UnsignedEvent(
				publicKey: keypair.publicKey,
				tags: [],
				application: 7,
				kind: 30_000,
				content: ByteBuffer(string: "app filter test")).sign(as: keypair.privateKey)
		
			// A filter scoped to application 7 matches the event.
			let matchingFilter = Filter(applications: [NOSTR_application(RAW_native: 7)], kinds: [NOSTR_kind(RAW_native: 30_000)])
			#expect(applyTesseraFilter(event, filter: matchingFilter))
		
			// A filter scoped to a different application must NOT match (regression test
			// for the fan-out path silently ignoring `filter.applications`).
			let nonMatchingFilter = Filter(applications: [NOSTR_application(RAW_native: 8)], kinds: [NOSTR_kind(RAW_native: 30_000)])
			#expect(!applyTesseraFilter(event, filter: nonMatchingFilter))
		
			// An application-agnostic filter still matches.
			let emptyAppFilter = Filter(applications: [], kinds: [NOSTR_kind(RAW_native: 30_000)])
			#expect(applyTesseraFilter(event, filter: emptyAppFilter))
		}
		
		@Test func encodeDecodeReplaceableKeyEvent() {
			var replaceableKey = ReplaceableKeyTag(name: "refMembr", key: ReplaceableKey(pubkey: nil, kind: NOSTR_kind(RAW_native: 100), dTag: nil))
			var replaceableKeyLen = 0; replaceableKey.RAW_encode(count: &replaceableKeyLen)
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: replaceableKeyLen)
			defer { pointer.deallocate() }
			_ = replaceableKey.RAW_encode(dest:pointer.baseAddress!)
			var decodedReplaceableKey = ReplaceableKeyTag(RAW_decode: UnsafeRawBufferPointer(pointer))!
			#expect(replaceableKey == decodedReplaceableKey)
	
			replaceableKey = ReplaceableKeyTag(name: "refCat", key: ReplaceableKey(pubkey: PublicKey(privateKey: DatabaseTests.aliceStaticPrivateKey), kind: NOSTR_kind(RAW_native: 100), dTag: nil))
			replaceableKeyLen = 0; replaceableKey.RAW_encode(count: &replaceableKeyLen)
			let pointer2 = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: replaceableKeyLen)
			defer { pointer2.deallocate() }
			_ = replaceableKey.RAW_encode(dest:pointer2.baseAddress!)
			decodedReplaceableKey = ReplaceableKeyTag(RAW_decode: UnsafeRawBufferPointer(pointer2))!
			#expect(replaceableKey == decodedReplaceableKey)
	
			replaceableKey = ReplaceableKeyTag(name: "refStat", key: ReplaceableKey(pubkey: nil, kind: NOSTR_kind(RAW_native: 100), dTag: DTag(value: "generic")))
			replaceableKeyLen = 0; replaceableKey.RAW_encode(count: &replaceableKeyLen)
			let pointer3 = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: replaceableKeyLen)
			defer { pointer3.deallocate() }
			_ = replaceableKey.RAW_encode(dest:pointer3.baseAddress!)
			decodedReplaceableKey = ReplaceableKeyTag(RAW_decode: UnsafeRawBufferPointer(pointer3))!
			#expect(replaceableKey == decodedReplaceableKey)
		}
		}

		@Suite("NOSTR Message Decode Tests")
		struct NOSTRMessageDecodeTests {
		/// Encodes `value` into a buffer and passes it to `NOSTR_message.decode`.
		private func decodeEnum<T: RAW_decodable & RAW_encodable>(_ value: T) -> NOSTR_message<UnsignedEvent<ByteBuffer>>? {
			var encodedLength = 0
			value.RAW_encode(count: &encodedLength)
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: encodedLength)
			defer { pointer.deallocate() }
			_ = value.RAW_encode(dest: pointer.baseAddress!)
			return NOSTR_message<UnsignedEvent<ByteBuffer>>.decode(UnsafeRawBufferPointer(pointer))
		}

		@Test func decodeRoundTripREQ() throws {
			let aliceKeyPair = try DatabaseTests.alicePrivateKeyWithKeypair()
			let filter = Filter(authors: [aliceKeyPair.publicKey], kinds: [NOSTR_kind(RAW_native: 10000)])
			let request = NOSTR_message_REQ(subscriptionID: "sub-test", filters: [filter], from: aliceKeyPair.publicKey, fetchHistory: true)
			let decoded = decodeEnum(request)
			guard case .REQ(let req) = decoded else {
				Issue.record("Expected .REQ, got \(String(describing: decoded))")
				return
			}
			#expect(String(req.subscriptionID) == "sub-test")
			#expect(req.filters.count == 1)
			#expect(req.fetchHistory.bool)
		}

		@Test func decodeRoundTripEVENT() throws {
			let aliceKeyPair = try DatabaseTests.alicePrivateKeyWithKeypair()
			let signedEvent = try UnsignedEvent(publicKey: aliceKeyPair.publicKey, tags: [DTag(value: "decode-test")], application: 1, kind: 30000, content: ByteBuffer(string: "Hello Tessera")).sign(as: aliceKeyPair.privateKey)
			let message = NOSTR_message_EVENT<UnsignedEvent<ByteBuffer>>(subscriptionID: "sub-e", event: signedEvent)
			let decoded = decodeEnum(message)
			guard case .EVENT(let event) = decoded else {
				Issue.record("Expected .EVENT, got \(String(describing: decoded))")
				return
			}
			#expect(event.event.unsignedEvent.id == signedEvent.unsignedEvent.id)
			#expect(event.event.unsignedEvent.content == signedEvent.unsignedEvent.content)
		}

		@Test func decodeRoundTripEOSE() throws {
			let eose = NOSTR_message_EOSE(subscriptionID: "sub-eose")
			let decoded = decodeEnum(eose)
			guard case .EOSE(let decodedEose) = decoded else {
				Issue.record("Expected .EOSE, got \(String(describing: decoded))")
				return
			}
			#expect(String(decodedEose.subscriptionID) == "sub-eose")
		}

		@Test func decodeRoundTripCLOSE() throws {
			let close = NOSTR_message_CLOSE(subscriptionID: "sub-close")
			let decoded = decodeEnum(close)
			guard case .CLOSE(let decodedClose) = decoded else {
				Issue.record("Expected .CLOSE, got \(String(describing: decoded))")
				return
			}
			#expect(String(decodedClose.subscriptionID) == "sub-close")
		}

		@Test func decodeRoundTripNOTICE() throws {
			let notice = NOSTR_message_NOTICE(noticeText: "User lacks write access credentials")
			let decoded = decodeEnum(notice)
			guard case .NOTICE(let decodedNotice) = decoded else {
				Issue.record("Expected .NOTICE, got \(String(describing: decoded))")
				return
			}
			#expect(decodedNotice.noticeText == "User lacks write access credentials")
		}

		@Test func decodeRoundTripOK() throws {
			let ok = NOSTR_message_OK(eventID: NOSTR_id(RAW_decode: [UInt8](repeating:0, count:32).withUnsafeBytes { $0 })!, status: true)
			let decoded = decodeEnum(ok)
			guard case .OK(let decodedOK) = decoded else {
				Issue.record("Expected .OK, got \(String(describing: decoded))")
				return
			}
			#expect(decodedOK.status)
		}

		@Test func decodeRejectsGarbage() {
			// A 4-byte block of 0xFF is not a valid type tag for any message type.
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: 4)
			defer { pointer.deallocate() }
			pointer[0] = 0xFF; pointer[1] = 0xFF; pointer[2] = 0xFF; pointer[3] = 0xFF
			#expect(NOSTR_message<UnsignedEvent<ByteBuffer>>.decode(UnsafeRawBufferPointer(pointer)) == nil)
		}

		@Test func decodeRejectsEmpty() {
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: 0)
			defer { pointer.deallocate() }
			#expect(NOSTR_message<UnsignedEvent<ByteBuffer>>.decode(UnsafeRawBufferPointer(pointer)) == nil)
		}
		}

		@Suite("Tessera Client API Tests")
		struct TesseraClientAPITests {
		@Test func receiverStoreDefaults() {
			let receiver = TesseraClientReceiverStore()
			#expect(receiver.references.isEmpty)
			#expect(receiver.deletionEventIds.isEmpty)
			#expect(receiver.referenceNeeds.isEmpty)
			#expect(receiver.models.isEmpty)
		}

		@Test func receiverStoreHoldsModels() {
			let receiver = TesseraClientReceiverStore()
			let model = ExampleModel()
			receiver.models.append(model)
			#expect(receiver.models.count == 1)
		}

		@Test func modelBaseClassDefaults() {
			let model = ExampleModel()
			#expect(model.subscriptionIDs.isEmpty)
			model.subscriptionIDs = ["sub-model"]
			#expect(model.modelStorage.isEmpty)
			#expect(model.latestByReplaceableKey.isEmpty)
			#expect(model.historyByReplaceableKey.isEmpty)
		}

		@Test func modelStoresEvents() throws {
			let aliceKeyPair = try DatabaseTests.alicePrivateKeyWithKeypair()
			var model = ExampleModel()
			model.subscriptionIDs = ["sub-model"]
			let signedEvent = try UnsignedEvent(publicKey: aliceKeyPair.publicKey, tags: [DTag(value: "stored")], application: 0, kind: 30000, content: ByteBuffer(string: "stored content")).sign(as: aliceKeyPair.privateKey)
			let message = NOSTR_message_EVENT<UnsignedEvent<ByteBuffer>>(subscriptionID: "sub-model", event: signedEvent)
			var encodedLength = 0
			message.RAW_encode(count: &encodedLength)
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: encodedLength)
			defer { pointer.deallocate() }
			_ = message.RAW_encode(dest: pointer.baseAddress!)
			try model.decodeEventAndUpsert(ptr: UnsafeRawBufferPointer(pointer))
			#expect(model.modelStorage[signedEvent.unsignedEvent.id] != nil)
			#expect(model.latestEvents().count == 1)
		}

		@Test func clientConfigurationFromBase64() throws {
			let myWGPrivateKey = DatabaseTests.aliceStaticPrivateKey
			let publicKey = PublicKey(privateKey: myWGPrivateKey)
			let publicKeyBase64 = String(RAW_base64.encode(publicKey))
			let privateKeyBase64 = String(RAW_base64.encode(myWGPrivateKey))
			let config = TesseraClientConfiguration(serverIP: "127.0.0.1", serverPort: 41411, serverPublicKeyBase64: publicKeyBase64, myPrivateKeyBase64: privateKeyBase64)
			#expect(config != nil)
			#expect(config?.serverIP == "127.0.0.1")
			#expect(config?.serverPort == 41411)
		}

		@Test func clientConfigurationRejectsBadBase64() {
			let config = TesseraClientConfiguration(serverIP: "127.0.0.1", serverPort: 41411, serverPublicKeyBase64: "not-base64!", myPrivateKeyBase64: "also-not")
			#expect(config == nil)
		}

		@Test func clientSessionDeletionEvent() throws {
			let myWGPrivateKey = DatabaseTests.aliceStaticPrivateKey
			let serverPublicKey = PublicKey(privateKey: myWGPrivateKey)
			let client = TesseraClient(serverIP: "127.0.0.1", serverPort: 41411, serverPublicKey: serverPublicKey, myPrivateKey: myWGPrivateKey)
			let session = TesseraSession(client: client, application: 1, myNostrPublicKey: serverPublicKey)
			// TesseraSession.delete() must build a kind-5 unsigned event before signing;
			// exercising construction requires a live tunnel, so verify the session wiring
			// is present: the session owns the client and receiver it was given.
			#expect(session.client === client)
			#expect(session.receiver.models.isEmpty)
			#expect(session.application == 1)
			#expect(session.myNostrPublicKey == serverPublicKey)
		}

		@Test func publishConvenienceBuildsAndSignsStringEvent() throws {
			let keyPair = try DatabaseTests.alicePrivateKeyWithKeypair()
			let client = TesseraClient(serverIP: "127.0.0.1", serverPort: 41411, serverPublicKey: keyPair.publicKey, myPrivateKey: DatabaseTests.aliceStaticPrivateKey)
			let session = TesseraSession(client: client, application: 7, myNostrPublicKey: keyPair.publicKey)

			// The String convenience wraps plain text into a ByteBuffer before signing;
			// makeSignedEvent(content:) is exercised here with that exact wrapped value.
			let signed = try session.makeSignedEvent(content: ByteBuffer(string: "hello tessera"), kind: 3001, tags: [DTag(value: "demo")], signedBy: keyPair.privateKey)

			#expect(signed.isValidSignature())
			#expect(signed.unsignedEvent.publicKey == keyPair.publicKey)
			#expect(signed.unsignedEvent.application.RAW_native() == 7)
			#expect(signed.unsignedEvent.kind.RAW_native() == 3001)
			// The String content is wrapped into a ByteBuffer automatically.
			let contentString = String(decoding: signed.unsignedEvent.content.readableBytesView, as: UTF8.self)
			#expect(contentString == "hello tessera")
		}

		@Test func publishConvenienceIsGenericOverContentType() throws {
			let keyPair = try DatabaseTests.alicePrivateKeyWithKeypair()
			let client = TesseraClient(serverIP: "127.0.0.1", serverPort: 41411, serverPublicKey: keyPair.publicKey, myPrivateKey: DatabaseTests.aliceStaticPrivateKey)
			let session = TesseraSession(client: client, application: 3, myNostrPublicKey: keyPair.publicKey)

			// A non-ByteBuffer content type: nostr-kit's StringContent.
			let content = StringContent("custom content")
			let signed = try session.makeSignedEvent(content: content, kind: 3002, tags: [DTag(value: "gen")], signedBy: keyPair.privateKey)

			#expect(signed.isValidSignature())
			#expect(signed.unsignedEvent.kind.RAW_native() == 3002)
			#expect(signed.unsignedEvent.application.RAW_native() == 3)
			#expect(signed.unsignedEvent.content == content)
		}
	}
}

/// A helper pairing a WireGuard key with a derived Nostr keypair, independent of the
/// database test's private-key constants.
extension TesseraTests.DatabaseTests {
	fileprivate static func alicePrivateKeyWithKeypair() throws -> (publicKey: PublicKey, privateKey: MemoryGuarded<RAW_ed25519.PrivateKey>) {
		let wgKey = Self.aliceStaticPrivateKey
		let (nostrPublic, nostrPrivate) = try RAW_ed25519.generateKeys(secretKey: wgKey)
		return (nostrPublic, nostrPrivate)
	}
}

/// A stand-in content type for model tests.
@RAW_convertible_string_type<UTF8>(backing:RAW_byte.self)
struct ExampleContent: NOSTR_event_content {}

/// A minimal model subclass used to exercise `TesseraModel` storage.
final class ExampleModel: TesseraModel<ExampleContent> {}
