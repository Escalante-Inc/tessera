import RAW
import NIO
import nostr_kit_swift

/// The primary value type for the tessera database.
/// Contains a nostr signed note and metadata for the note.
public struct StoredSignedEvent:Sendable, Hashable, RAW_convertible, RAW_accessible {
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
			guard let decoded = StoredSignedEvent(
				RAW_decode: readPtr,
				count: count
			) else {
				fatalError("RAW_access_mutating produced invalid state")
			}

			self = decoded
			return result
		}
	}
	
	public let event: NOSTR_event_signed<UnsignedEvent<ByteBuffer>>
	public let metadata: SignedEventMetadata
	
	public init(event: NOSTR_event_signed<UnsignedEvent<ByteBuffer>>, metadata: SignedEventMetadata) {
		self.event = event
		self.metadata = metadata
	}
	
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		guard count >= MemoryLayout<Bytes4>.size else { return nil }
		let eventLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		var dataCount = count - MemoryLayout<Bytes4>.size
		guard dataCount >= eventLength else { return nil }
		guard let event = NOSTR_event_signed<UnsignedEvent<ByteBuffer>>(RAW_decode: inputPtr, count: eventLength) else { return nil }
		inputPtr = inputPtr.advanced(by: eventLength)
		self.event = event
		
		guard dataCount >= MemoryLayout<Bytes4>.size else { return nil }
		let metadataLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		dataCount = count - MemoryLayout<Bytes4>.size
		guard dataCount >= metadataLength else { return nil }
		guard let metadata = SignedEventMetadata(RAW_decode: inputPtr, count: metadataLength) else { return nil }
		self.metadata = metadata
	}
	
	public func RAW_encode(count: inout RAW.size_t) {
		count += (MemoryLayout<Bytes4>.size * 2)
		event.RAW_encode(count: &count)
		metadata.RAW_encode(count: &count)
	}
	
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var eventLength = 0; event.RAW_encode(count: &eventLength)
		let eventLengthBytes = Bytes4(RAW_native: UInt32(eventLength))
		var dest = eventLengthBytes.RAW_encode(dest: dest)
		dest = event.RAW_encode(dest: dest)
		
		var metadataLength = 0; metadata.RAW_encode(count: &metadataLength)
		let metadataLengthBytes = Bytes4(RAW_native: UInt32(metadataLength))
		dest = metadataLengthBytes.RAW_encode(dest: dest)
		dest = metadata.RAW_encode(dest: dest)
		return dest
	}
}
