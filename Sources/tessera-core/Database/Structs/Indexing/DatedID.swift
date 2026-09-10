import Foundation
import RAW
import QuickLMDB
import nostr_kit_swift

internal struct DatedID: Hashable, RAW_accessible, RAW_decodable, RAW_encodable, MDB_comparable {
	let date: NOSTR_date
	let id: NOSTR_id
	
	init(date: NOSTR_date, id: NOSTR_id) {
		self.date = date
		self.id = id
	}
	
	public init?(RAW_decode buffer:UnsafeRawBufferPointer) {
		guard buffer.count == MemoryLayout<NOSTR_date>.size + MemoryLayout<NOSTR_id>.size else { return nil }
		var seekPtr = buffer.baseAddress!
		self.date = NOSTR_date(RAW_staticbuff_seeking: &seekPtr)
		self.id = NOSTR_id(RAW_staticbuff_seeking: &seekPtr)
	}
	
	public func RAW_encode(count: inout Int) {
		count += MemoryLayout<NOSTR_date>.size + MemoryLayout<NOSTR_id>.size
	}
	
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		let dest = date.RAW_encode(dest: dest)
		return id.RAW_encode(dest: dest)
	}

	@discardableResult
	public func RAW_encode(_: UnsafeMutableRawPointer.Type, destination: UnsafeMutableRawPointer) -> UnsafeMutableRawPointer {
		return UnsafeMutableRawPointer(RAW_encode(dest: destination.assumingMemoryBound(to: UInt8.self)))
	}
	
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
