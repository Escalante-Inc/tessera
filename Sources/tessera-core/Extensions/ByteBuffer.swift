import RAW
import NIO
import NIOCore
import nostr_kit_swift

extension ByteBuffer: @retroactive RAW_decodable {
	/// Decodes a `ByteBuffer` from raw bytes: the whole buffer becomes the payload.
	public init?(RAW_decode buffer: UnsafeRawBufferPointer) {
		var decoded = ByteBufferAllocator().buffer(capacity: buffer.count)
		decoded.writeBytes(buffer)
		self = decoded
	}
}

extension ByteBuffer: @retroactive RAW_encodable {
	public func RAW_encode(count: inout Int) {
		count += self.readableBytes
	}

	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var tmp = self
		let written = tmp.readWithUnsafeReadableBytes { srcPtr in
			let src = srcPtr.bindMemory(to: UInt8.self)
			dest.update(from: src.baseAddress!, count: src.count)
			return src.count
		}
		return dest.advanced(by: written)
	}
	@discardableResult
	public func RAW_encode(_: UnsafeMutableRawPointer.Type, destination: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
		return UnsafeMutableRawPointer(RAW_encode(dest: destination.assumingMemoryBound(to: UInt8.self)))
	}


}

extension ByteBuffer: @retroactive NOSTR_event_content {
	// `RAW_decodable`/`RAW_encodable` conformances above satisfy the protocol
	// requirements (`RAW_decodable` + `RAW_encodable` + `Sendable` + `Hashable`).
}

public extension ByteBuffer {
	/// Initialize a ByteBuffer using an object that conforms to `RAW_encodable`
	init<T:RAW_encodable>(rawObject: T) {
		var size: Int = 0
		rawObject.RAW_encode(count: &size)
		var buffer = ByteBufferAllocator().buffer(capacity: size)
		buffer.writeWithUnsafeMutableBytes(minimumWritableBytes: size) { ptr in
			guard let baseAddress = ptr.baseAddress else { return 0 }
			_ = rawObject.RAW_encode(UnsafeMutableRawPointer.self, destination: baseAddress)
			return size
		}
		self = buffer
	}
}
