import RAW
import RAW_dh25519
import nostr_kit_swift

/// The basic Tessera user information.
/// This is the content posted in a kind 0 (profile) note.
public struct User: RAW_convertible, RAW_accessible {
	public var userName: EncodedString
	
	public init(userName:String) {
		self.userName = EncodedString(userName)
	}
	
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		guard count >= MemoryLayout<Bytes2>.size else { return nil }
		let userNameLength = Int(Bytes2(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		let dataCount = count - MemoryLayout<Bytes2>.size
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
