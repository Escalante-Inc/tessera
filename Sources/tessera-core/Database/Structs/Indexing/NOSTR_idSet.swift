import RAW
import RAW_dh25519
import nostr_kit_swift

public struct NOSTR_idSet: RAW_convertible, RAW_accessible {
	public func RAW_access<R, E>(_ body: (UnsafeBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E : Error {
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
	
	public mutating func RAW_access_mutating<R, E>(_ body: (UnsafeMutableBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E : Error {
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
			guard let decoded = NOSTR_idSet(
				RAW_decode: readPtr,
				count: count
			) else {
				fatalError("RAW_access_mutating produced invalid state")
			}

			self = decoded
			return result
		}
	}
	
	public var ids: Set<NOSTR_id>
	
	public init(ids: Set<NOSTR_id>) {
		self.ids = ids
	}
	
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		guard count >= MemoryLayout<Bytes4>.size else { return nil }
		let numIds = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		var dataCount = count - MemoryLayout<Bytes4>.size
		
		self.ids = []
		for _ in 0..<numIds {
			guard dataCount >= MemoryLayout<NOSTR_id>.size else { return nil }
			self.ids.insert(NOSTR_id(RAW_staticbuff_seeking: &inputPtr))
			dataCount -= MemoryLayout<NOSTR_id>.size
		}
	}
	
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<Bytes4>.size + (MemoryLayout<NOSTR_id>.size * ids.count)
	}
	
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		let idsLength = Bytes4(RAW_native: UInt32(ids.count))
		var dest = idsLength.RAW_encode(dest: dest)
		for id in ids {
			dest = id.RAW_encode(dest: dest)
		}
		return dest
	}
}
