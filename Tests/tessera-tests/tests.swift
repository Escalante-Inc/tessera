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
				publicKey: aliceEd25519PublicKey, date: NOSTR_date(date: Date()),
				tags: [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Alice Tag"])],
				kind: NOSTR_kind(RAW_native: 999), content: ByteBuffer(string: "Alice Content")).sign(as: aliceEd25519PrivateKey)
			bobSignedEvent = try UnsignedEvent(
				publicKey: bobEd25519PublicKey, date: NOSTR_date(date: Date()),
				tags: [EventTag(user: aliceEd25519PublicKey), EventTag(tagName: "b", tagValues: ["Bob Tag"])],
				kind: NOSTR_kind(RAW_native: 998), content: ByteBuffer(string: "Bob Content")).sign(as: bobEd25519PrivateKey)
			adminSignedEvent = try UnsignedEvent(
				publicKey: adminEd25519PublicKey, date: NOSTR_date(date: Date()),
				tags: [EventTag(user: aliceEd25519PublicKey), EventTag(user: bobEd25519PublicKey), EventTag(tagName: "ad", tagValues: ["Admin Tag"])],
				kind: NOSTR_kind(RAW_native: 999), content: ByteBuffer(string: "Admin Content")).sign(as: adminEd25519PrivateKey)
			try tesseraDB.scribeNewEvent(signedEvent: StoredSignedEvent(event: aliceSignedEvent, metadata: SignedEventMetadata(tombstone: false, receivedFromRelay: "alice")), logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: StoredSignedEvent(event: bobSignedEvent, metadata: SignedEventMetadata(tombstone: false, receivedFromRelay: "bob")), logLevel: .trace)
			try tesseraDB.scribeNewEvent(signedEvent: StoredSignedEvent(event: adminSignedEvent, metadata: SignedEventMetadata(tombstone: false, receivedFromRelay: "admin")), logLevel: .trace)
			
			try tesseraDB.scribeNewUser(user: User(privateKey: alicePrivateKey, userName: "Alice"), logLevel: .trace)
			try tesseraDB.scribeNewUser(user: User(privateKey: bobPrivateKey, userName: "Bob"), logLevel: .trace)
			try tesseraDB.scribeNewUser(user: User(privateKey: adminPrivateKey, userName: "Admin"), logLevel: .trace)
		}
		
		deinit {
			do {
				try TesseraDB.deleteEnvironment(base: base, environment: "tessera", logLevel: .trace)
			} catch {
				cliLogger.error(Logger.Message.red("Failed to delete the testing database at \(String(describing: base.path))"))
			}
		}
				
		@Test func testForceUpdateEvent() throws {
			tesseraDB.forceUpdateEvent(id: aliceSignedEvent.unsignedEvent.id, admin: adminPrivateKey, newContent: ByteBuffer(string:"New Alice Content"))
			var filter = Filter(authors: [aliceEd25519PublicKey])
			var events = try tesseraDB.queryEventsByFilter(filter: [filter])
			#expect(events.count == 1)
			#expect(events[0].event.unsignedEvent.content == ByteBuffer(string: "New Alice Content"))
			
			tesseraDB.forceUpdateEvent(id: bobSignedEvent.unsignedEvent.id, admin: adminPrivateKey)
			filter = Filter(tags: [try createAdminTag(admin: adminPrivateKey)])
			events = try tesseraDB.queryEventsByFilter(filter: [filter])
			#expect(events.count == 2)
		}
		
		@Test func testForceUpdateEventFiltered() throws {
			let filter = Filter(kinds: [NOSTR_kind(RAW_native: 999)])
			tesseraDB.forceUpdateEventFiltered(filters: [filter], admin: adminPrivateKey, newContent: ByteBuffer(string: "New Content"))
			let events = try tesseraDB.queryEventsByFilter(filter: [filter])
			#expect(events.count == 2)
			for event in events {
				#expect(event.event.unsignedEvent.content == ByteBuffer(string: "New Content"))
			}
		}
		
		@Test func testForceUpdateEventAddTags() throws {
			var aliceBaseTags = [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Alice Tag"])]
			let addedTags = [EventTag(tagName: "n1", tagValues: ["New Tag 1"]), EventTag(tagName: "n2", tagValues: ["New Tag 2"])]
			tesseraDB.forceUpdateEvent(id: aliceSignedEvent.unsignedEvent.id, admin: adminPrivateKey, addTags: addedTags)
			aliceBaseTags.append(contentsOf: addedTags)
			let filter = Filter(authors: [aliceEd25519PublicKey], tags: aliceBaseTags)
			let events = try tesseraDB.queryEventsByFilter(filter: [filter])
			#expect(events.count == 1)
		}
		
		@Test func testForceUpdateEventRemoveTags() throws {
			var aliceBaseTags = [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Alice Tag"])]
			let removedTags = [EventTag(tagName: "a", tagValues: ["Alice Tag"])]
			tesseraDB.forceUpdateEvent(id: aliceSignedEvent.unsignedEvent.id, admin: adminPrivateKey, removeTags: removedTags)
			var filter = Filter(authors: [aliceEd25519PublicKey], tags: aliceBaseTags)
			var events = try tesseraDB.queryEventsByFilter(filter: [filter])
			#expect(events.count == 0)
			aliceBaseTags.remove(at: 1)
			filter = Filter(authors: [aliceEd25519PublicKey], tags: aliceBaseTags)
			events = try tesseraDB.queryEventsByFilter(filter: [filter])
			#expect(events.count == 1)
		}
		
		@Test func testForceUpdateEventOverwriteTags() throws {
			let aliceBaseTags = [EventTag(user: bobEd25519PublicKey), EventTag(tagName: "a", tagValues: ["Alice Tag"])]
			let overwriteTags = [EventTag(tagName: "o", tagValues: ["Overwrite Tag"])]
			tesseraDB.forceUpdateEvent(id: aliceSignedEvent.unsignedEvent.id, admin: adminPrivateKey, overwriteTags: overwriteTags)
			var filter = Filter(authors: [aliceEd25519PublicKey], tags: aliceBaseTags)
			var events = try tesseraDB.queryEventsByFilter(filter: [filter])
			#expect(events.count == 0)
			filter = Filter(authors: [aliceEd25519PublicKey], tags: overwriteTags)
			events = try tesseraDB.queryEventsByFilter(filter: [filter])
			#expect(events.count == 1)
		}
		
		@Test func testForceUpdateUser() throws {
			tesseraDB.forceUpdateUser(publicEd25519Key: aliceEd25519PublicKey, username: "New Alice")
			let alice = try tesseraDB.queryUser(publicKey: aliceEd25519PublicKey)
			#expect(alice.userName == "New Alice")
		}
		
		@Test func testForceDeleteUserByPK() {
			tesseraDB.forceDeleteUser(publicKey: aliceEd25519PublicKey)
			#expect(tesseraDB.userCount == 2)
		}
		
		@Test func testForceDeleteUserByUsername() {
			tesseraDB.forceDeleteUser(username: "Alice")
			#expect(tesseraDB.userCount == 2)
		}
		
		@Test func forceDeleteEvent() {
			tesseraDB.forceDeleteEvent(id: aliceSignedEvent.unsignedEvent.id)
			#expect(tesseraDB.eventCount == 2)
		}
		
		@Test func forceDeleteEventFiltered() {
			tesseraDB.forceDeleteEventFiltered(filters: [Filter(kinds: [NOSTR_kind(RAW_native: 999)])])
			#expect(tesseraDB.eventCount == 1)
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
			let user = User(privateKey: DatabaseTests.aliceStaticPrivateKey, userName: "Alice")
			var userLen = 0; user.RAW_encode(count: &userLen)
			let pointer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: userLen)
			defer { pointer.deallocate() }
			_ = user.RAW_encode(dest:pointer.baseAddress!)
			let decodedUser = User(RAW_decode: pointer.baseAddress!, count: userLen)!
			#expect(user.userName == decodedUser.userName)
		}
		
		@Test func userRAWaccess() throws {
			let user = User(privateKey: DatabaseTests.aliceStaticPrivateKey, userName: "Bob")
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
