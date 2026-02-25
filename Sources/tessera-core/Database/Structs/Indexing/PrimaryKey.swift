import Foundation
import RAW
import RAW_dh25519
import QuickLMDB
import nostr_kit_swift

internal struct ReplaceableKey: Hashable, MDB_comparable, RAW_accessible, RAW_convertible {
	public func RAW_access<R, E>(_ body: (UnsafeBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E : Swift.Error {
		var count: RAW.size_t = 0
		self.RAW_encode(count: &count)
		
		return try! withUnsafeTemporaryAllocation(
			byteCount: count,
			alignment: MemoryLayout<UInt8>.alignment
		) { rawBuffer in
			let base = rawBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
			_ = self.RAW_encode(dest: base)

			let buffer = UnsafeBufferPointer(start: base, count: count)
			return try body(buffer)
		}
	}
	
	public mutating func RAW_access_mutating<R, E>(_ body: (UnsafeMutableBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E : Swift.Error {
		var count: RAW.size_t = 0
		self.RAW_encode(count: &count)

		return try! withUnsafeTemporaryAllocation(
			byteCount: count,
			alignment: MemoryLayout<UInt8>.alignment
		) { rawBuffer in
			let base = rawBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
			_ = self.RAW_encode(dest: base)

			let buffer = UnsafeMutableBufferPointer(start: base, count: count)
			let result = try body(buffer)

			let readPtr = UnsafeRawPointer(base)
			guard let decoded = ReplaceableKey(
				RAW_decode: readPtr,
				count: count
			) else {
				fatalError("RAW_access_mutating produced invalid state")
			}

			self = decoded
			return result
		}
	}
	
	let pubkey: PublicKey
	let kind: NOSTR_kind
	let dTag: (any NOSTR_tag_value)?
	
	init(pubkey: PublicKey, kind: NOSTR_kind, dTag: (any NOSTR_tag_value)?) {
		self.pubkey = pubkey
		self.kind = kind
		self.dTag = dTag
	}
	
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		guard count >= MemoryLayout<PublicKey>.size + MemoryLayout<NOSTR_kind>.size + MemoryLayout<EncodedBool>.size else { return nil }
		self.pubkey = PublicKey(RAW_staticbuff_seeking: &inputPtr)
		self.kind = NOSTR_kind(RAW_staticbuff_seeking: &inputPtr)
		let dTagExists = EncodedBool(RAW_staticbuff_seeking: &inputPtr)
		var dataCount = count - MemoryLayout<PublicKey>.size + MemoryLayout<NOSTR_kind>.size + MemoryLayout<EncodedBool>.size
		
		if dTagExists.bool {
			let dTagLength = Int(Bytes2(RAW_staticbuff_seeking: &inputPtr).RAW_native())
			dataCount = count - MemoryLayout<Bytes2>.size
			guard dataCount == dTagLength else { return nil }
			let dTag = NOSTR_tag_generic_value(RAW_decode: inputPtr, count: dTagLength)
			inputPtr = inputPtr.advanced(by: dTagLength)
			self.dTag = dTag
		} else {
			dTag = nil
		}
	}
	
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<PublicKey>.size + MemoryLayout<NOSTR_kind>.size + MemoryLayout<EncodedBool>.size
		if dTag != nil {
			count += MemoryLayout<Bytes2>.size
			dTag!.RAW_encode(count: &count)
		}
	}
	
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var dest = pubkey.RAW_encode(dest: dest)
		dest = kind.RAW_encode(dest: dest)
		if dTag != nil {
			dest = EncodedBool(true).RAW_encode(dest: dest)
			var dTagLength = 0; dTag!.RAW_encode(count: &dTagLength)
			let dTagLengthBytes = Bytes2(RAW_native: UInt16(dTagLength))
			var dest = dTagLengthBytes.RAW_encode(dest: dest)
			dest = dTag!.RAW_encode(dest: dest)
		} else {
			dest = EncodedBool(false).RAW_encode(dest: dest)
		}
		return dest
	}
	
	public static var MDB_compare_f: MDB_compare_ftype {
		return { lhs, rhs in
		   guard let lhs = lhs, let rhs = rhs else {
			   return 0
		   }
		   let lsize = lhs.pointee.mv_size
		   let rsize = rhs.pointee.mv_size

		   let lptr = lhs.pointee.mv_data!
		   let rptr = rhs.pointee.mv_data!

		   let minSize = min(lsize, rsize)

		   let cmp = memcmp(lptr, rptr, minSize)
		   if cmp != 0 {
			   return Int32(cmp)
		   }
		   if lsize < rsize { return -1 }
		   if lsize > rsize { return 1 }
		   return 0
	   }
	}
	
	static func == (lhs: Self, rhs: Self) -> Bool {
		guard lhs.pubkey == rhs.pubkey,
			  lhs.kind == rhs.kind else {
			return false
		}
		switch (lhs.dTag, rhs.dTag) {
			case (nil, nil):
				return true
			case (nil, _), (_, nil):
				return false
			case let (l?, r?):
				var equal = true
				l.RAW_access { lPtr in
					r.RAW_access { rPtr in
						if lPtr.count != rPtr.count {
							equal = false
							return
						}
						equal = lPtr.elementsEqual(rPtr)
					}
				}
				return equal
		}
	}

	func hash(into hasher: inout Hasher) {
		hasher.combine(pubkey)
		hasher.combine(kind)

		guard let dTag else {
			hasher.combine(0 as UInt8)
			return
		}
		hasher.combine(1 as UInt8)

		dTag.RAW_access { ptr in
			hasher.combine(ptr.count)
			for byte in ptr {
				hasher.combine(byte)
			}
		}
	}
}
