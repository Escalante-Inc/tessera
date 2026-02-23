import RAW
import NIO
import NIOCore
import nostr_kit_swift

extension ByteBuffer: @retroactive RAW_decodable {}
extension ByteBuffer: @retroactive RAW_encodable {}
extension ByteBuffer: @retroactive NOSTR_event_content {
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		let length = Int(count)
		guard length >= 0 else { return nil }

		var buffer = ByteBufferAllocator().buffer(capacity: length)

		let rawBuffer = UnsafeRawBufferPointer(start: inputPtr, count: length)
		buffer.writeBytes(rawBuffer)

		self = buffer
	}

	public func RAW_encode(count: inout RAW.size_t) {
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
}
