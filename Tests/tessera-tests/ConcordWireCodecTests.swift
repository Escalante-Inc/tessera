import Testing
import Foundation
import NIO
import RAW
import QuickLMDB
import nostr_kit_swift
import concord
@testable import tessera_core

private func testKey(_ byte: UInt8, offset: UInt8 = 0) -> NOSTR_id {
	var bytes = [UInt8](repeating: byte, count: 32)
	bytes[31] = offset
	return NOSTR_id(RAW_decode: bytes.withUnsafeBytes { $0 })!
}

private func testFingerprint(_ byte: UInt8) -> Fingerprint {
	let bytes = [UInt8](repeating: byte, count: 24)
	return bytes.withUnsafeBytes { raw -> Fingerprint in
		var cursor = raw.baseAddress!
		return Fingerprint(RAW_staticbuff_seeking: &cursor)
	}
}

private func assertRoundTrip<Key: ConcordKey, Value: MDB_convertible>(_ message: ConcordMessage<Key, Value>) throws {
	let frame = try ConcordWireCodec.encode(message)
	let decoded = try ConcordWireCodec.decode(frame) as ConcordMessage<Key, Value>
	let reEncoded = try ConcordWireCodec.encode(decoded)
	#expect(frame == reEncoded)
}

@Suite("Concord Wire Codec Tests")
struct ConcordWireCodecTests {
	/// Encode → decode → re-encode must be byte-identical for every section kind.
	@Test func roundTripsAllSectionKinds() throws {
		typealias Key = NOSTR_id
		typealias Value = TesseraSignedEvent
		let sections: [ConcordSection<Key>] = [
			.skip(nil),
			.skip(testKey(1)),
			.fingerprint(nil, testFingerprint(2)),
			.fingerprint(testKey(3), testFingerprint(4)),
			.idList(nil, []),
			.idList(testKey(5), [testKey(6), testKey(7, offset: 9)]),
		]
		let message: ConcordMessage<Key, Value> = .reconcile(ConcordReconcile(sections: sections))
		try assertRoundTrip(message)
	}

	/// dataQuery and finish round-trip (the leaf message shapes).
	@Test func roundTripsDataQueryAndFinish() throws {
		try assertRoundTrip(ConcordMessage<NOSTR_id, TesseraSignedEvent>.dataQuery(testKey(8)))
		try assertRoundTrip(ConcordMessage<NOSTR_id, TesseraSignedEvent>.finish)
	}

	/// A `.data` payload survives byte-for-byte, including zero bytes and 0xFF.
	@Test func roundTripsDataPreservesValueBytesVerbatim() throws {
		let payload: [UInt8] = [0x00, 0xFF, 0x42, 0x01, 0x02, 0x03, 0x04]
		let frame = try ConcordWireCodec.encode(ConcordMessage<NOSTR_id, TesseraSignedEvent>.data(key: testKey(9), bytes: ConcordOwnedBytes(payload)))
		let decoded = try ConcordWireCodec.decode(frame) as ConcordMessage<NOSTR_id, TesseraSignedEvent>
		let reEncoded = try ConcordWireCodec.encode(decoded)
		#expect(frame == reEncoded)
		guard case .data(_, let bytes) = decoded else {
			Issue.record("expected .data message")
			return
		}
		let got = try ConcordOwnedBytes(bytes).withUnsafeBytes { Array($0) }
		#expect(got == payload)
	}

	/// Every strict prefix of a valid frame must reject — never trap and never
	/// silently decode a shorter message.
	@Test func rejectsEveryTruncatedPrefix() throws {
		let frame = try ConcordWireCodec.encode(ConcordMessage<NOSTR_id, TesseraSignedEvent>.reconcile(ConcordReconcile(sections: [
			.skip(testKey(1)),
			.fingerprint(testKey(2), testFingerprint(3)),
		])))
		var sawBadMagic = false
		for cut in 0..<frame.readableBytes {
			let prefix = frame.getSlice(at: 0, length: cut)!
			do {
				_ = try ConcordWireCodec.decode(prefix) as ConcordMessage<NOSTR_id, TesseraSignedEvent>
				Issue.record("prefix of length \(cut) unexpectedly decoded")
			} catch let error as ConcordWireError {
				if error == .badMagic { sawBadMagic = true }
			} catch {
				Issue.record("unexpected non-ConcordWireError at cut \(cut): \(error)")
			}
		}
		#expect(sawBadMagic)
	}

	/// Unknown version, unknown message type, and wrong magic all fail loudly.
	@Test func rejectsUnknownVersionTypeAndMagic() throws {
		var badVersion = ByteBufferAllocator().buffer(capacity: 32)
		badVersion.writeBytes(ConcordWireCodec.magicBytes)
		badVersion.writeInteger(UInt8(2))
		badVersion.writeInteger(UInt8(0x04))
		#expect(throws: ConcordWireError.badVersion(2)) {
			_ = try ConcordWireCodec.decode(badVersion) as ConcordMessage<NOSTR_id, TesseraSignedEvent>
		}

		var badType = ByteBufferAllocator().buffer(capacity: 32)
		badType.writeBytes(ConcordWireCodec.magicBytes)
		badType.writeInteger(ConcordWireCodec.version)
		badType.writeInteger(UInt8(0x7F))
		#expect(throws: ConcordWireError.badType(0x7F)) {
			_ = try ConcordWireCodec.decode(badType) as ConcordMessage<NOSTR_id, TesseraSignedEvent>
		}

		var badMagic = ByteBufferAllocator().buffer(capacity: 32)
		badMagic.writeBytes(Array("NOGT".utf8))
		badMagic.writeInteger(ConcordWireCodec.version)
		badMagic.writeInteger(UInt8(0x04))
		#expect(throws: ConcordWireError.badMagic) {
			_ = try ConcordWireCodec.decode(badMagic) as ConcordMessage<NOSTR_id, TesseraSignedEvent>
		}
	}

	/// An absurd `idList` count must be rejected before any allocation is made
	/// from the attacker-controlled value.
	@Test func rejectsGiantIdListCount() throws {
		var frame = ByteBufferAllocator().buffer(capacity: 64)
		frame.writeBytes(ConcordWireCodec.magicBytes)
		frame.writeInteger(ConcordWireCodec.version)
		frame.writeInteger(UInt8(0x01))
		frame.writeInteger(UInt32(1))
		frame.writeInteger(UInt8(0x02))
		frame.writeInteger(UInt8(0))
		frame.writeInteger(UInt32.max)
		#expect(throws: ConcordWireError.truncated) {
			_ = try ConcordWireCodec.decode(frame) as ConcordMessage<NOSTR_id, TesseraSignedEvent>
		}
	}
}
