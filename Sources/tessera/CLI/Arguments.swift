import ArgumentParser
import Logging
import RAW
import RAW_dh25519
import RAW_base64

extension RAW_dh25519.PublicKey:@retroactive ExpressibleByArgument {
	public init?(argument: String) {
		let rawBytes = try? RAW_base64.decode(argument)
		guard let bytes = rawBytes, bytes.count == 32 else {
			return nil
		}
		self = bytes.withUnsafeBytes { RAW_dh25519.PublicKey(RAW_decode: $0)! }
	}
}

extension MemoryGuarded<RAW_dh25519.PrivateKey>:@retroactive ExpressibleByArgument {
	public convenience init?(argument: String) {
		let rawBytes = try? RAW_base64.decode(argument)
		guard let bytes = rawBytes, bytes.count == 32 else {
			return nil
		}
		let buffer = UnsafeMutableRawPointer.allocate(byteCount: bytes.count, alignment: 1)
		buffer.copyMemory(from: bytes, byteCount: bytes.count)
		defer { buffer.deallocate() }
		self.init(RAW_decode: UnsafeRawBufferPointer(start: buffer, count: bytes.count))!
	}
}

extension Logger.Level:@retroactive ExpressibleByArgument {
	public init?(argument: String) {
		switch argument.lowercased() {
		case "trace": self = .trace
		case "debug": self = .debug
		case "info": self = .info
		case "notice", "notify": self = .notice
		case "warning", "warn": self = .warning
		case "error": self = .error
		case "critical", "fatal": self = .critical
		default: return nil
		}
	}
}
