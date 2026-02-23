import RAW
import nostr_kit_swift

public struct SignedEventMetadata:Sendable, Hashable, RAW_convertible {
	let tombstone: EncodedBool
	let receivedFromRelay: EncodedString
	
	public init(tombstone: Bool, receivedFromRelay: String) {
		self.tombstone = EncodedBool(tombstone)
		self.receivedFromRelay = EncodedString(stringLiteral: receivedFromRelay)
	}
	
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		guard count >= MemoryLayout<EncodedBool>.size else { return nil }
		tombstone = EncodedBool(RAW_staticbuff_seeking: &inputPtr)
		var dataCount = count - MemoryLayout<EncodedBool>.size
		
		guard dataCount >= MemoryLayout<Bytes2>.size else { return nil }
		let receivedFromRelayLength = Int(Bytes2(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		dataCount -= MemoryLayout<Bytes2>.size
		guard dataCount == receivedFromRelayLength else { return nil }
		let receivedFromRelay = EncodedString(RAW_decode: inputPtr, count: receivedFromRelayLength)
		inputPtr = inputPtr.advanced(by: receivedFromRelayLength)
		self.receivedFromRelay = receivedFromRelay
	}
	
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<EncodedBool>.size + MemoryLayout<Bytes2>.size
		receivedFromRelay.RAW_encode(count: &count)
	}
	
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var dest = tombstone.RAW_encode(dest: dest)
		
		var receivedFromRelayLength = 0; receivedFromRelay.RAW_encode(count: &receivedFromRelayLength)
		let receivedFromRelayLengthBytes = Bytes2(RAW_native: UInt16(receivedFromRelayLength))
		dest = receivedFromRelayLengthBytes.RAW_encode(dest: dest)
		dest = receivedFromRelay.RAW_encode(dest: dest)
		return dest
	}
}

