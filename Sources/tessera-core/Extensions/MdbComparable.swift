import Foundation
import RAW_base64
import RAW
import RAW_dh25519
import QuickLMDB
import nostr_kit_swift

extension NOSTR_id {
	public var debugDescription:String {
		return "\(String(RAW_base64.encode(self)))"
	}
}
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

extension NOSTR_application: @retroactive MDB_comparable {
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
