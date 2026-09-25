import NIO
import RAW
import QuickLMDB
import concord

/// Errors thrown while framing/unframing tessera concord messages on the wire.
public enum ConcordWireError: Swift.Error, Equatable {
	/// The frame did not start with the "NEGT" magic.
	case badMagic
	/// The frame advertised an unsupported protocol version.
	case badVersion(UInt8)
	/// The frame contained an unknown section tag or message type.
	case badType(UInt8)
	/// The frame ran out of bytes in the middle of a message.
	case truncated
}

/// Wire codec v1 for tessera-to-tessera concord synchronization.
///
/// One message per WireGuard datagram:
///
///     "NEGT" (4) | version (1) | msgType (1) | payload
///     msgType: 0x01 reconcile | 0x02 dataQuery | 0x03 data | 0x04 finish
///
/// All integers are big-endian. Bounds travel as full raw key bytes (no
/// common-prefix compression — concord leaves that to the transport, and this
/// transport deliberately does not need it). `.data` value bytes are copied
/// into the frame at send time — the single sanctioned copy.
///
/// Decoding is structural only: lengths and tags are validated, but ordering
/// invariants (strictly increasing section bounds, monotonic `dataQuery`
/// keys) are enforced by the concord engine, which aborts the round's write
/// transaction on violation.
public enum ConcordWireCodec {
	public static let magicBytes: [UInt8] = Array("NEGT".utf8)
	public static let version: UInt8 = 1

	private static let fingerprintByteCount = 24

	// MARK: Encode

	public static func encode<Key: ConcordKey, Value: MDB_convertible>(_ message: ConcordMessage<Key, Value>) throws -> ByteBuffer {
		var buf = ByteBufferAllocator().buffer(capacity: 4096)
		buf.writeBytes(Self.magicBytes)
		buf.writeInteger(Self.version)
		switch message {
		case .reconcile(let reconcile):
			buf.writeInteger(UInt8(0x01))
			buf.writeInteger(UInt32(reconcile.sections.count))
			for section in reconcile.sections {
				encodeSection(section, into: &buf)
			}
		case .dataQuery(let key):
			buf.writeInteger(UInt8(0x02))
			writeKey(key, into: &buf)
		case .data(let key, let bytes):
			buf.writeInteger(UInt8(0x03))
			writeKey(key, into: &buf)
			let owned = try ConcordOwnedBytes(bytes)
			owned.withUnsafeBytes { raw in
				buf.writeInteger(UInt32(raw.count))
				buf.writeBytes(raw)
			}
		case .finish:
			buf.writeInteger(UInt8(0x04))
		}
		return buf
	}

	private static func encodeSection<Key: ConcordKey>(_ section: ConcordSection<Key>, into buf: inout ByteBuffer) {
		switch section {
		case .skip(let bound):
			buf.writeInteger(UInt8(0x00))
			writeOptionalBound(bound, into: &buf)
		case .fingerprint(let bound, let fingerprint):
			buf.writeInteger(UInt8(0x01))
			writeOptionalBound(bound, into: &buf)
			_ = fingerprint.RAW_access_immutable(UnsafeBufferPointer<UInt8>.self) { buf.writeBytes($0) }
		case .idList(let bound, let ids):
			buf.writeInteger(UInt8(0x02))
			writeOptionalBound(bound, into: &buf)
			buf.writeInteger(UInt32(ids.count))
			for id in ids {
				writeKey(id, into: &buf)
			}
		}
	}

	private static func writeOptionalBound<Key: ConcordKey>(_ bound: Key?, into buf: inout ByteBuffer) {
		if let bound {
			buf.writeInteger(UInt8(1))
			writeKey(bound, into: &buf)
		} else {
			buf.writeInteger(UInt8(0))
		}
	}

	private static func writeKey<Key: ConcordKey>(_ key: Key, into buf: inout ByteBuffer) {
		_ = key.RAW_access_immutable(UnsafeBufferPointer<UInt8>.self) { buf.writeBytes($0) }
	}

	// MARK: Decode

	public static func decode<Key: ConcordKey, Value: MDB_convertible>(_ frame: ByteBuffer) throws -> ConcordMessage<Key, Value> {
		var buf = frame
		guard let magic = buf.readBytes(length: Self.magicBytes.count), magic == Self.magicBytes else {
			throw ConcordWireError.badMagic
		}
		guard let v = buf.readInteger(as: UInt8.self) else { throw ConcordWireError.truncated }
		guard v == Self.version else { throw ConcordWireError.badVersion(v) }
		guard let type = buf.readInteger(as: UInt8.self) else { throw ConcordWireError.truncated }

		switch type {
		case 0x01:
			guard let count = buf.readInteger(as: UInt32.self) else { throw ConcordWireError.truncated }
			// Each section encodes at least a tag byte plus a bound flag byte.
			guard count <= buf.readableBytes / 2 else { throw ConcordWireError.truncated }
			var sections: [ConcordSection<Key>] = []
			sections.reserveCapacity(Int(count))
			for _ in 0..<Int(count) {
				sections.append(try decodeSection(&buf))
			}
			return .reconcile(ConcordReconcile(sections: sections))
		case 0x02:
			return .dataQuery(try decodeKey(&buf))
		case 0x03:
			let key: Key = try decodeKey(&buf)
			guard let length = buf.readInteger(as: UInt32.self) else { throw ConcordWireError.truncated }
			guard let valueBytes = buf.readBytes(length: Int(length)) else { throw ConcordWireError.truncated }
			return .data(key: key, bytes: ConcordOwnedBytes(valueBytes))
		case 0x04:
			return .finish
		default:
			throw ConcordWireError.badType(type)
		}
	}

	private static func decodeSection<Key: ConcordKey>(_ buf: inout ByteBuffer) throws -> ConcordSection<Key> {
		guard let tag = buf.readInteger(as: UInt8.self) else { throw ConcordWireError.truncated }
		switch tag {
		case 0x00:
			let bound: Key? = try decodeOptionalBound(&buf)
			return .skip(bound)
		case 0x01:
			let bound: Key? = try decodeOptionalBound(&buf)
			guard let fpBytes = buf.readBytes(length: Self.fingerprintByteCount), fpBytes.count == Self.fingerprintByteCount else { throw ConcordWireError.truncated }
			// `Fingerprint` (a concord staticbuff) exposes only the seeking
			// initializer; the byte count is guarded above.
			let fingerprint = fpBytes.withUnsafeBytes { raw -> Fingerprint in
				var cursor = raw.baseAddress!
				return Fingerprint(RAW_staticbuff_seeking: &cursor)
			}
			return .fingerprint(bound, fingerprint)
		case 0x02:
			let bound: Key? = try decodeOptionalBound(&buf)
			guard let count = buf.readInteger(as: UInt32.self) else { throw ConcordWireError.truncated }
			let keySize = MemoryLayout<Key>.size
			guard count <= buf.readableBytes / keySize else { throw ConcordWireError.truncated }
			var ids: [Key] = []
			ids.reserveCapacity(Int(count))
			for _ in 0..<Int(count) {
				ids.append(try decodeKey(&buf))
			}
			return .idList(bound, ids)
		default:
			throw ConcordWireError.badType(tag)
		}
	}

	private static func decodeOptionalBound<Key: ConcordKey>(_ buf: inout ByteBuffer) throws -> Key? {
		guard let flag = buf.readInteger(as: UInt8.self) else { throw ConcordWireError.truncated }
		switch flag {
		case 0:
			return nil
		case 1:
			return try decodeKey(&buf)
		default:
			throw ConcordWireError.badType(flag)
		}
	}

	private static func decodeKey<Key: ConcordKey>(_ buf: inout ByteBuffer) throws -> Key {
		let keySize = MemoryLayout<Key>.size
		guard let bytes = buf.readBytes(length: keySize), bytes.count == keySize else { throw ConcordWireError.truncated }
		return bytes.withUnsafeBytes { raw -> Key in
			var cursor = raw.baseAddress!
			return Key(RAW_staticbuff_seeking: &cursor)
		}
	}
}
