import RAW
import RAW_dh25519
import nostr_kit_swift

@RAW_staticbuff(bytes: 32)
public struct UserAccessLevel: Sendable, NOSTR_tag_value {
	public init(accessLevels: [UInt8]) {
		var bitArray = [UInt8](repeating: 0, count: 32)
		for level in accessLevels {
			let byteIndex = Int(level) / 8
			let bitIndex  = Int(level) % 8
			bitArray[byteIndex] |= 1 << bitIndex
		}
		self.init(RAW_staticbuff: bitArray)
	}
}

@NostrTag(name: "readAL")
public struct ReadAccessLevels: Sendable, Hashable, NOSTR_tag {
	public var indexField = NOSTR_tag_name(string: "readAL")!
	public var value: UserAccessLevel
	public init(value: UserAccessLevel) {
		self.value = value
	}
}

@NostrTag(name: "writeAL")
public struct WriteAccessLevels: Sendable, Hashable, NOSTR_tag {
	public var indexField = NOSTR_tag_name(string: "writeAL")!
	public var value: UserAccessLevel
	public init(value: UserAccessLevel) {
		self.value = value
	}
}

/// The basic Tessera user information.
/// This is the content posted in a kind 0 (profile) note.
public struct User: RAW_convertible, RAW_accessible {
	public var userName: Encoded.String
	
	public init(userName:String) {
		self.userName = Encoded.String(userName)
	}
	
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		guard count >= MemoryLayout<Bytes2>.size else { return nil }
		let userNameLength = Int(Bytes2(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		let dataCount = count - MemoryLayout<Bytes2>.size
		guard dataCount == userNameLength else { return nil }
		let userName = Encoded.String(RAW_decode: inputPtr, count: userNameLength)
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
