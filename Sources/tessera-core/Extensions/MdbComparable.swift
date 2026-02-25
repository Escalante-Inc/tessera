import Foundation
import RAW_base64
import RAW
import RAW_dh25519
import QuickLMDB
import nostr_kit_swift

extension NOSTR_id:@retroactive MDB_comparable {
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
}
extension NOSTR_id {
	public var debugDescription:String {
		return "\(String(RAW_base64.encode(self)))"
	}
}
extension PublicKey: @retroactive MDB_comparable {
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
}

extension NOSTR_kind: @retroactive MDB_comparable {
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
}

extension NOSTR_date: @retroactive MDB_comparable {
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
}

extension EventTag: @retroactive MDB_comparable {
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
}

extension EventTag: @retroactive RAW_accessible {
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
			guard let decoded = EventTag(
				RAW_decode: readPtr,
				count: count
			) else {
				fatalError("RAW_access_mutating produced invalid state")
			}

			self = decoded
			return result
		}
	}
}
