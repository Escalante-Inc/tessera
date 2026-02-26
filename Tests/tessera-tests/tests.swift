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
			self.tesseraDB = try TesseraDB(base: base, memoryMapSize: size_t(base.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .trace)
			aliceSignedEvent = try UnsignedEvent(
				publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -1, to: Date())!),
				tags: [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Alice Tag"])],
				kind: NOSTR_kind(RAW_native: 10000), content: ByteBuffer(string: "Alice Content")).sign(as: aliceEd25519PrivateKey)
			bobSignedEvent = try UnsignedEvent(
				publicKey: bobEd25519PublicKey, date: NOSTR_date(date: Date()),
				tags: [EventTag(user: aliceEd25519PublicKey), EventTag(tagName: "b", tagValues: ["Bob Tag"]), EventTag(dTag: "testUniqueDTag")],
				kind: NOSTR_kind(RAW_native: 30000), content: ByteBuffer(string: "Bob Content")).sign(as: bobEd25519PrivateKey)
			adminSignedEvent = try UnsignedEvent(
				publicKey: adminEd25519PublicKey, date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: 1, to: Date())!),
				tags: [EventTag(user: aliceEd25519PublicKey), EventTag(user: bobEd25519PublicKey), EventTag(tagName: "ad", tagValues: ["Admin Tag"])],
				kind: NOSTR_kind(RAW_native: 10000), content: ByteBuffer(string: "Admin Content")).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: aliceSignedEvent, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: bobSignedEvent, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: adminSignedEvent, logLevel: .trace)
			
			aliceProfileEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventTag(accessLevel: 3)], kind: NOSTR_kind(RAW_native: 0), content: ByteBuffer(rawObject: User(userName: "Alice"))).sign(as: aliceEd25519PrivateKey)
			bobProfileEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [EventTag(accessLevel: 3)], kind: NOSTR_kind(RAW_native: 0), content: ByteBuffer(rawObject: User(userName: "Bob"))).sign(as: bobEd25519PrivateKey)
			adminProfileEvent = try UnsignedEvent(publicKey: adminEd25519PublicKey, tags: [EventTag(accessLevel: 7)], kind: NOSTR_kind(RAW_native: 0), content: ByteBuffer(rawObject: User(userName: "Admin"))).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: aliceProfileEvent, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: bobProfileEvent, logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: adminProfileEvent, logLevel: .trace)
		}
		
		deinit {
			do {
				try TesseraDB.deleteEnvironment(base: base, environment: "tessera", logLevel: .trace)
			} catch {
				cliLogger.error(Logger.Message.red("Failed to delete the testing database at \(String(describing: base.path))"))
			}
		}
		
		@Test func writeDeletionEvent() throws {
			let validDeletionEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventTag(eventID: aliceSignedEvent.unsignedEvent.id)], kind: NOSTR_kind(RAW_native: 5), content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: validDeletionEvent, logLevel: .trace)
			#expect(tesseraDB.eventCount == 7)
			
			let invalidKeyDeletionEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [EventTag(eventID: aliceSignedEvent.unsignedEvent.id)], kind: NOSTR_kind(RAW_native: 5), content: ByteBuffer()).sign(as: bobEd25519PrivateKey)
			#expect(throws: SignedNoteError.invalidKind5PublicKey) {
				try tesseraDB.scribeNewEvent(signedEvent: invalidKeyDeletionEvent, logLevel: .trace)
			}
			
			let invalidTagDeletionEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventTag(eventID: invalidKeyDeletionEvent.unsignedEvent.id)], kind: NOSTR_kind(RAW_native: 5), content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
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
			
			let combinedFilterE = Filter(authors: [aliceEd25519PublicKey, bobEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0), NOSTR_kind(RAW_native: 10000)], tags: [EventTag(accessLevel: 3)])
			let combinedFilterF = Filter(authors: [aliceEd25519PublicKey, bobEd25519PublicKey], kinds: [NOSTR_kind(RAW_native: 0), NOSTR_kind(RAW_native: 10000)], tags: [EventTag(tagName: "a", tagValues: ["Alice Tag"])])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterE, combinedFilterF])
			#expect(events.count == 3)
			
			let combinedFilterG = Filter(ids: [aliceSignedEvent.unsignedEvent.id, bobSignedEvent.unsignedEvent.id], authors: [aliceEd25519PublicKey])
			events = try tesseraDB.queryEventsBySmartFilter(filters: [combinedFilterG])
			#expect(events.count == 1)
		}
		
		@Test func smartFilterWithUpdates() throws {
			let updatedEvent = try UnsignedEvent( publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Date()),
				tags: [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["New Alice Tag"])],
				kind: NOSTR_kind(RAW_native: 10000), content: ByteBuffer(string: "New Alice Content")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: updatedEvent, logLevel: .trace)
			let filter = Filter(authors: [aliceEd25519PublicKey], tags:[EventTag(user: bobEd25519PublicKey)])
			var events = try tesseraDB.queryEventsBySmartFilter(filters: [filter])
			#expect(events.count == 1)
			#expect(events[0].unsignedEvent.content == ByteBuffer(string: "New Alice Content"))
			
			let updatedEvent2 = try UnsignedEvent( publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Date()),
				tags: [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Newer Alice Tag"])],
				kind: NOSTR_kind(RAW_native: 10000), content: ByteBuffer(string: "Newer Alice Content")).sign(as: aliceEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: updatedEvent2, logLevel: .trace)
			events = try tesseraDB.queryEventsBySmartFilter(filters: [filter])
			#expect(events.count == 1)
			#expect(events[0].unsignedEvent.content == ByteBuffer(string: "Newer Alice Content"))
		}
		
		@Test func smartFilterWithDeletions() throws {
			let aliceDeletionEvent = try UnsignedEvent(publicKey: aliceEd25519PublicKey, tags: [EventTag(eventID: aliceSignedEvent.unsignedEvent.id), EventTag(eventID: aliceProfileEvent.unsignedEvent.id)], kind: NOSTR_kind(RAW_native: 5), content: ByteBuffer()).sign(as: aliceEd25519PrivateKey)
			let bobDeletionEvent = try UnsignedEvent(publicKey: bobEd25519PublicKey, tags: [EventTag(eventID: bobSignedEvent.unsignedEvent.id)], kind: NOSTR_kind(RAW_native: 5), content: ByteBuffer()).sign(as: bobEd25519PrivateKey)
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
		
		@Test func fillDatabaseWithData() throws {
			let authors = [(aliceEd25519PublicKey, aliceEd25519PrivateKey), (bobEd25519PublicKey, bobEd25519PrivateKey), (adminEd25519PublicKey, adminEd25519PrivateKey)]
			let tagValues = ["Tag0", "Tag1", "Tag2", "Tag3", "Tag4", "Tag5", "Tag6", "Tag7", "Tag8", "Tag9"]
			let tagNames: [Character] = Array("abcefghijklmnopqrstuvwxyz")
			
			for _ in 0..<20_000 {
				let author = authors.randomElement()!
				let kind = Int.random(in: [10_000...19_999, 30_000...39_999].randomElement()!)
				let signedEvent = try UnsignedEvent(
					publicKey: author.0,
					date: NOSTR_date(date: Calendar.current.date(byAdding: .day, value: -1, to: Date())!),
					tags: [EventTag(tagName: String(tagNames.randomElement()!), tagValues: [tagValues.randomElement()!]),
						   kind > 20_000 ? EventTag(tagName: "d", tagValues: [tagValues.randomElement()!]) :
							EventTag(tagName: String(tagNames.randomElement()!), tagValues: [tagValues.randomElement()!])],
					kind: NOSTR_kind(RAW_native: UInt16(kind)),
					content: ByteBuffer(string: "")).sign(as: author.1)
				try tesseraDB.scribeNewEvent(signedEvent: signedEvent, logLevel: .warning)
			}
			
			cliLogger.info("Database Size: ")
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
	}
}
