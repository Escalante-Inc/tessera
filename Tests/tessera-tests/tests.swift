import Testing
import Logging
import Foundation
import NIO
import RAW
import RAW_base64
import RAW_dh25519
import RAW_ed25519
import bedrock
import nostr_kit_swift
@testable import tessera_core

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
		
		static let aliceStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI="), count:32)!
		static let bobStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("SD/y8yQa/DgiYRnDI9vJEiGezNn4yLd/4yL9OLnej0A="), count:32)!
		static let adminStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("EEug1Qbe4WjR1TDq4iN4Ce4Rh5iN4aDR407/e5bQgW4="), count:32)!

		let aliceEd25519PublicKey:PublicKey
		let aliceEd25519PrivateKey:MemoryGuarded<Ed25519.PrivateKey>
		let alicePrivateKey:MemoryGuarded<PrivateKey>
		
		let bobEd25519PublicKey:PublicKey
		let bobEd25519PrivateKey:MemoryGuarded<Ed25519.PrivateKey>
		let bobPrivateKey:MemoryGuarded<PrivateKey>
		
		let adminEd25519PublicKey:PublicKey
		let adminEd25519PrivateKey:MemoryGuarded<Ed25519.PrivateKey>
		let adminPrivateKey:MemoryGuarded<PrivateKey>
		
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
			(aliceEd25519PublicKey, aliceEd25519PrivateKey) = try Ed25519.generateKeys(secretKey: alicePrivateKey)
			(bobEd25519PublicKey, bobEd25519PrivateKey) = try Ed25519.generateKeys(secretKey: bobPrivateKey)
			(adminEd25519PublicKey, adminEd25519PrivateKey) = try Ed25519.generateKeys(secretKey: adminPrivateKey)
			self.tesseraDB = try TesseraDB(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error)
			
			aliceProfileEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventTag(tagName: "readAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0])]), EventTag(tagName: "writeAccessLevels", tagValues: [UserAccessLevel(accessLevels: [1])])], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Alice"))).sign(as: aliceEd25519PrivateKey)
			bobProfileEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [EventTag(tagName: "readAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0,1])]), EventTag(tagName: "writeAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0,2])])], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Bob"))).sign(as: bobEd25519PrivateKey)
			adminProfileEvent = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [EventTag(tagName: "readAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0,1,2,255])]), EventTag(tagName: "writeAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0,1,2,255])])], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Admin"))).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .info)
			try tesseraDB.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .info)
			try tesseraDB.scribeNewUser(signedEvent: adminProfileEvent, logLevel: .info)
			
			aliceSignedEvent = try UnsignedEvent(
				publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -1, to: Date())!),
				tags: [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Alice Tag"])], application: 0,
				kind: 10000, content: ByteBuffer(string: "Alice Content")).sign(as: aliceEd25519PrivateKey)
			bobSignedEvent = try UnsignedEvent(
				publicKey: bobEd25519PublicKey, date: NOSTR_date(date: Date()),
				tags: [EventTag(user: aliceEd25519PublicKey), EventTag(tagName: "b", tagValues: ["Bob Tag"]), EventTag(dTag: "testUniqueDTag")], application: 1,
				kind: 30000, content: ByteBuffer(string: "Bob Content")).sign(as: bobEd25519PrivateKey)
			adminSignedEvent = try UnsignedEvent(
				publicKey: adminEd25519PublicKey, date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: 1, to: Date())!),
				tags: [EventTag(user: aliceEd25519PublicKey), EventTag(user: bobEd25519PublicKey), EventTag(tagName: "ad", tagValues: ["Admin Tag"])], application: 0,
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
			let validDeletionEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventTag(eventID: aliceSignedEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: validDeletionEvent, logLevel: .trace)
			#expect(tesseraDB.eventCount == 7)
			
			let invalidKeyDeletionEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [EventTag(eventID: aliceSignedEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: bobEd25519PrivateKey)
			#expect(throws: SignedNoteError.invalidKind5PublicKey) {
				try tesseraDB.scribeNewEvent(signedEvent: invalidKeyDeletionEvent, logLevel: .trace)
			}
			
			let invalidTagDeletionEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventTag(eventID: invalidKeyDeletionEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
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
			let tagFilterA = Filter(tags: [EventTag(user: aliceEd25519PublicKey)])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [tagFilterA])
			#expect(events.count == 2)
			
			let tagFilterB = Filter(tags: [EventTag(user: aliceEd25519PublicKey), EventTag(user: bobEd25519PublicKey), EventTag(tagName: "ad", tagValues: ["Admin Tag"])])
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
			
			let combinedFilterB = Filter(authors: [aliceEd25519PublicKey], tags: [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Alice Tag"])], until: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: 1, to: Date())!))
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterB])
			#expect(events.count == 1)
			
			let combinedFilterC = Filter(authors: [aliceEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0)], tags: [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Alice Tag"])], until: NOSTR_date(date: Calendar.current.date(byAdding: .hour, value: 1, to: Date())!))
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterC])
			#expect(events.count == 0)
			
			let combinedFilterD = Filter(authors: [aliceEd25519PublicKey, bobEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0), NOSTR_kind(RAW_native: 10000)])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterD])
			#expect(events.count == 3)
			
			let combinedFilterE = Filter(authors: [aliceEd25519PublicKey, adminEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0), NOSTR_kind(RAW_native: 10000)], tags: [EventTag(tagName: "ad", tagValues: ["Admin Tag"])])
			let combinedFilterF = Filter(authors: [aliceEd25519PublicKey, adminEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0), NOSTR_kind(RAW_native: 10000)], tags: [EventTag(tagName: "a", tagValues: ["Alice Tag"])])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterE, combinedFilterF])
			#expect(events.count == 2)
			
			let combinedFilterG = Filter(ids: [aliceSignedEvent.unsignedEvent.id, bobSignedEvent.unsignedEvent.id], authors: [aliceEd25519PublicKey])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterG])
			#expect(events.count == 1)
		}
		
		@Test func smartFilterWithUpdates() throws {
			let updatedEvent = try UnsignedEvent( publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Date()),
												  tags: [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["New Alice Tag"])], application: 0,
				kind: 10000, content: ByteBuffer(string: "New Alice Content")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: updatedEvent, logLevel: .trace)
			let filter = Filter(authors: [aliceEd25519PublicKey], tags:[EventTag(user: bobEd25519PublicKey)])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [filter])
			#expect(events.count == 1)
			#expect(events[0].unsignedEvent.content == ByteBuffer(string: "New Alice Content"))
			
			let updatedEvent2 = try UnsignedEvent( publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Date()),
												   tags: [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Newer Alice Tag"])], application: 0,
				kind: 10000, content: ByteBuffer(string: "Newer Alice Content")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: updatedEvent2, logLevel: .trace)
			events = try tesseraDB.queryEventsBySmartFilter(filters: [filter])
			#expect(events.count == 1)
			#expect(events[0].unsignedEvent.content == ByteBuffer(string: "Newer Alice Content"))
		}
		
		@Test func smartFilterWithDeletions() throws {
			let aliceDeletionEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventTag(eventID: aliceSignedEvent.unsignedEvent.id), EventTag(eventID: aliceProfileEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
			let bobDeletionEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [EventTag(eventID: bobSignedEvent.unsignedEvent.id)], application: 0, kind: 5, content: ByteBuffer()).sign(as: bobEd25519PrivateKey)
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
	}
}

extension TesseraTests {
	@Suite("Large Data Tests", .serialized)
	class LargeDataTests {
		let cliLogger:Logger
		let base = Path(FileManager.default.homeDirectoryForCurrentUser.path)
		let tesseraDB:TesseraDB
		
		static let aliceStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("8DFnI7tPWLl4WmuEp4T5KVuKMW6iyjRdTb3IVaDe+kI="), count:32)!
		static let bobStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("SD/y8yQa/DgiYRnDI9vJEiGezNn4yLd/4yL9OLnej0A="), count:32)!
		static let adminStaticPrivateKey = MemoryGuarded<PrivateKey>(RAW_decode:try! RAW_base64.decode("EEug1Qbe4WjR1TDq4iN4Ce4Rh5iN4aDR407/e5bQgW4="), count:32)!

		let aliceEd25519PublicKey:PublicKey
		let aliceEd25519PrivateKey:MemoryGuarded<Ed25519.PrivateKey>
		let alicePrivateKey:MemoryGuarded<PrivateKey>
		
		let bobEd25519PublicKey:PublicKey
		let bobEd25519PrivateKey:MemoryGuarded<Ed25519.PrivateKey>
		let bobPrivateKey:MemoryGuarded<PrivateKey>
		
		let adminEd25519PublicKey:PublicKey
		let adminEd25519PrivateKey:MemoryGuarded<Ed25519.PrivateKey>
		let adminPrivateKey:MemoryGuarded<PrivateKey>
		
		init() throws {
			var buildLogger = Logger(label:"\(String(describing:Self.self))")
			buildLogger.logLevel = .debug
			cliLogger = buildLogger
			alicePrivateKey = Self.aliceStaticPrivateKey
			bobPrivateKey = Self.bobStaticPrivateKey
			adminPrivateKey = Self.adminStaticPrivateKey
			(aliceEd25519PublicKey, aliceEd25519PrivateKey) = try Ed25519.generateKeys(secretKey: alicePrivateKey)
			(bobEd25519PublicKey, bobEd25519PrivateKey) = try Ed25519.generateKeys(secretKey: bobPrivateKey)
			(adminEd25519PublicKey, adminEd25519PrivateKey) = try Ed25519.generateKeys(secretKey: adminPrivateKey)
			self.tesseraDB = try TesseraDB(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .error)
		}
		
		@Test func fillDatabaseWithData() throws {
			let aliceProfileEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventTag(tagName: "readAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0])]), EventTag(tagName: "writeAccessLevels", tagValues: [UserAccessLevel(accessLevels: [1])])], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Alice"))).sign(as: aliceEd25519PrivateKey)
			let bobProfileEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [EventTag(tagName: "readAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0,1])]), EventTag(tagName: "writeAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0,2])])], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Bob"))).sign(as: bobEd25519PrivateKey)
			let adminProfileEvent = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [EventTag(tagName: "readAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0,1,2,255])]), EventTag(tagName: "writeAccessLevels", tagValues: [UserAccessLevel(accessLevels: [0,1,2,255])])], application: 0, kind: 0, content: ByteBuffer(rawObject: User(userName: "Admin"))).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewUser(signedEvent: aliceProfileEvent, logLevel: .info)
			try tesseraDB.scribeNewUser(signedEvent: bobProfileEvent, logLevel: .info)
			try tesseraDB.scribeNewUser(signedEvent: adminProfileEvent, logLevel: .info)
			let authors = [(aliceEd25519PublicKey, aliceEd25519PrivateKey), (bobEd25519PublicKey, bobEd25519PrivateKey), (adminEd25519PublicKey, adminEd25519PrivateKey)]
			let tagValues = ["Tag0", "Tag1", "Tag2", "Tag3", "Tag4", "Tag5", "Tag6", "Tag7", "Tag8", "Tag9"]
			let tagNames: [Character] = Array("abcefghijklmnopqrstuvwxyz")
			
			for _ in 0..<50_000 {
				let author = authors.randomElement()!
				let kind = UInt32.random(in: [10_000...24_999, 30_000...39_999].randomElement()!)
				let application = UInt16.random(in: UInt16.min...UInt16.max)
				let signedEvent = try UnsignedEvent(
					publicKey: author.0,
					date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: Int.random(in: -365...365), to: Date())!),
					tags: [EventTag(tagName: String(tagNames.randomElement()!), tagValues: [tagValues.randomElement()!]),
						   kind > 14_999 ? EventTag(tagName: "d", tagValues: [tagValues.randomElement()!]) :
							EventTag(tagName: String(tagNames.randomElement()!), tagValues: [tagValues.randomElement()!])], application: application,
					kind: kind,
					content: ByteBuffer(string: "")).sign(as: author.1)
				try tesseraDB.scribeNewEvent(signedEvent: signedEvent, logLevel: .warning)
			}
			
			cliLogger.info("Database Size: ")
		}
		
		@Test func smartFilter() throws {
			let filterA = Filter(authors: [aliceEd25519PublicKey], tags: [EventTag(tagName: "a", tagValues: ["Tag0"])])
			let filterB = Filter(authors: [aliceEd25519PublicKey, bobEd25519PublicKey],
								 since: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -50, to: Date())!),
								 until: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: 50, to: Date())!))
			let events = try tesseraDB.queryEventsBySmartFilter(filters: [filterA, filterB])
			cliLogger.info("Found \(events.count) events")
		}
		
		@Test func dumbFilter() throws {
			let filterA = Filter(authors: [aliceEd25519PublicKey], tags: [EventTag(tagName: "a", tagValues: ["Tag0"])])
			let filterB = Filter(authors: [aliceEd25519PublicKey, bobEd25519PublicKey],
								 since: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -50, to: Date())!),
								 until: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: 50, to: Date())!))
			let events = try tesseraDB.queryEventsByDumbFilter(filters: [filterA, filterB])
			cliLogger.info("Found \(events.count) events")
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
			let decodedByteBuffer = ByteBuffer(RAW_decode: pointer.baseAddress!, count: byteBufferLen)!
			#expect(byteBuffer == decodedByteBuffer)
		}
		
		@Test func encodeDecodeUser() {
			let user = User(userName: "Alice")
			var userLen = 0; user.RAW_encode(count: &userLen)
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: userLen)
			defer { pointer.deallocate() }
			_ = user.RAW_encode(dest:pointer.baseAddress!)
			let decodedUser = User(RAW_decode: pointer.baseAddress!, count: userLen)!
			#expect(user.userName == decodedUser.userName)
		}
		
		@Test func userRAWaccess() throws {
			let user = User(userName: "Bob")
			var userLen = 0; user.RAW_encode(count: &userLen)
			let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: userLen)
			defer { buffer.deallocate() }
			_ = user.RAW_encode(dest:buffer.baseAddress!)
			user.RAW_access { ptr in
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
			var decodedReplaceableKey = ReplaceableKey(RAW_decode: pointer.baseAddress!, count: replaceableKeyLen)!
			#expect(replaceableKey == decodedReplaceableKey)
			
			replaceableKey = ReplaceableKey(pubkey: PublicKey(privateKey: DatabaseTests.aliceStaticPrivateKey), kind: NOSTR_kind(RAW_native: 100), dTag: nil)
			replaceableKeyLen = 0; replaceableKey.RAW_encode(count: &replaceableKeyLen)
			let pointer2 = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: replaceableKeyLen)
			defer { pointer2.deallocate() }
			_ = replaceableKey.RAW_encode(dest:pointer2.baseAddress!)
			decodedReplaceableKey = ReplaceableKey(RAW_decode: pointer2.baseAddress!, count: replaceableKeyLen)!
			#expect(replaceableKey == decodedReplaceableKey)
		}
		
		@Test func encodeDecodeReplaceableKeyEvent() {
			var replaceableKey = EventTag(identifier: "refMembr", reference: ReplaceableKey(pubkey: nil, kind: NOSTR_kind(RAW_native: 100), dTag: nil))
			var replaceableKeyLen = 0; replaceableKey.RAW_encode(count: &replaceableKeyLen)
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: replaceableKeyLen)
			defer { pointer.deallocate() }
			_ = replaceableKey.RAW_encode(dest:pointer.baseAddress!)
			var decodedReplaceableKey = EventTag(RAW_decode: pointer.baseAddress!, count: replaceableKeyLen)!
			#expect(replaceableKey == decodedReplaceableKey)
			
			replaceableKey = EventTag(identifier: "refCat", reference: ReplaceableKey(pubkey: PublicKey(privateKey: DatabaseTests.aliceStaticPrivateKey), kind: NOSTR_kind(RAW_native: 100), dTag: nil))
			replaceableKeyLen = 0; replaceableKey.RAW_encode(count: &replaceableKeyLen)
			let pointer2 = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: replaceableKeyLen)
			defer { pointer2.deallocate() }
			_ = replaceableKey.RAW_encode(dest:pointer2.baseAddress!)
			decodedReplaceableKey = EventTag(RAW_decode: pointer2.baseAddress!, count: replaceableKeyLen)!
			#expect(replaceableKey == decodedReplaceableKey)
			
			replaceableKey = EventTag(identifier: "refStat", reference: ReplaceableKey(pubkey: nil, kind: NOSTR_kind(RAW_native: 100), dTag: NOSTR_tag_generic_value("generic")))
			replaceableKeyLen = 0; replaceableKey.RAW_encode(count: &replaceableKeyLen)
			let pointer3 = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: replaceableKeyLen)
			defer { pointer3.deallocate() }
			_ = replaceableKey.RAW_encode(dest:pointer3.baseAddress!)
			decodedReplaceableKey = EventTag(RAW_decode: pointer3.baseAddress!, count: replaceableKeyLen)!
			#expect(replaceableKey == decodedReplaceableKey)
		}
	}
}
