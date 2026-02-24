import RAW
import RAW_dh25519
import nostr_kit_swift

public struct User: RAW_convertible, RAW_accessible {
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
			guard let decoded = User(
				RAW_decode: readPtr,
				count: count
			) else {
				fatalError("RAW_access_mutating produced invalid state")
			}

			self = decoded
			return result
		}
	}
	
	public var userName: EncodedString
	
	public init(userName:String) {
		self.userName = EncodedString(userName)
	}
	
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		guard count >= MemoryLayout<Bytes2>.size else { return nil }
		let userNameLength = Int(Bytes2(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		var dataCount = count - MemoryLayout<Bytes2>.size
		guard dataCount == userNameLength else { return nil }
		let userName = EncodedString(RAW_decode: inputPtr, count: userNameLength)
		inputPtr = inputPtr.advanced(by: userNameLength)
		self.userName = userName
	}
	
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<Bytes2>.size
		userName.RAW_encode(count: &count)
	}
	
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var userNameLength = 0; userName.RAW_encode(count: &userNameLength)
		let userNameLengthBytes = Bytes2(RAW_native: UInt16(userNameLength))
		var dest = userNameLengthBytes.RAW_encode(dest: dest)
		dest = userName.RAW_encode(dest: dest)
		return dest
	}
}
