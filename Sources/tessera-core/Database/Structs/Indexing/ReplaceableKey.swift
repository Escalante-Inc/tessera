import Foundation
import RAW
import RAW_dh25519
import QuickLMDB
import nostr_kit_swift

public struct ReplaceableKeyTag: Sendable, Hashable, NOSTR_tag {
	public var indexField: NOSTR_tag_name
	public var value: ReplaceableKey
	public init(name: String, key: ReplaceableKey) {
		self.indexField = NOSTR_tag_name(string: name)!
		self.value = key
	}
}
	
extension ReplaceableKeyTag: RAW_convertible {
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		var dataCount = count
		guard dataCount >= MemoryLayout<NOSTR_tag_name>.size else {
			return nil
		}

		self.indexField = NOSTR_tag_name(RAW_staticbuff_seeking: &inputPtr)
		dataCount -= MemoryLayout<NOSTR_tag_name>.size
		guard let indexString = indexField.string else { return nil }
		guard indexString.starts(with: "ref") else { return nil }

		guard dataCount >= MemoryLayout<Bytes4>.size else {
			return nil
		}
		dataCount -= MemoryLayout<Bytes4>.size
		let length = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		guard dataCount >= length else {
			return nil
		}
		dataCount -= length
		guard let value = ReplaceableKey(RAW_decode: inputPtr, count: length) else {
			return nil
		}
		guard dataCount == 0 else {
			return nil
		}
		self.value = value
	}
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<NOSTR_tag_name>.size + MemoryLayout<Bytes4>.size
		value.RAW_encode(count: &count)
	}
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var dest = indexField.RAW_encode(dest: dest)

		var tagValueLength = 0;
		value.RAW_encode(count: &tagValueLength)
		let tagValueLengthBytes = Bytes4(RAW_native: UInt32(tagValueLength))
		dest = tagValueLengthBytes.RAW_encode(dest: dest)
		dest = value.RAW_encode(dest: dest)

		return dest
	}
}

public struct ReplaceableKey: Hashable, MDB_comparable, RAW_accessible, RAW_convertible, NOSTR_tag_value {
	let pubkey: PublicKey?
	let kind: NOSTR_kind
	let dTag: DTag?
	
	public init(pubkey: PublicKey?, kind: NOSTR_kind, dTag: DTag?) {
		self.pubkey = pubkey
		self.kind = kind
		self.dTag = dTag
	}
	
	public init<ContentType: NOSTR_event_content>(event: UnsignedEvent<ContentType>) throws {
		self.kind = event.kind
		let kindInt = kind.RAW_native() % 40_000
		if NostrKindCategory.replaceablePKKindDTag.range.contains(kindInt) ||
		   NostrKindCategory.replaceablePKDTag.range.contains(kindInt) {
			var foundDTag: DTag? = nil
			for tag in event.tags.array {
				if let dTag = tag.unwrap(as: DTag.self) {
					foundDTag = dTag
					break
				}
			}
			guard let dTag = foundDTag else {
				throw SignedNoteError.invalidParameterizedEvent
			}
			self.dTag = dTag
		} else {
			self.dTag = nil
		}

		if NostrKindCategory.replaceablePKDTag.range.contains(kindInt) {
			self.pubkey = nil
		} else {
			self.pubkey = event.publicKey
		}
	}
	
	public init?(tagValue: any NOSTR_tag_value) {
		let key = tagValue.RAW_access { ptr in
			ReplaceableKey(RAW_decode: ptr.baseAddress!, count: ptr.count)
		}
		if key == nil {
			return nil
		} else {
			self = key!
		}
	}
	
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		var inputPtr = inputPtr
		guard count > MemoryLayout<Encoded.Bool>.size else { return nil }
		let pubKeyExists = Encoded.Bool(RAW_staticbuff_seeking: &inputPtr)
		var dataCount = count - MemoryLayout<Encoded.Bool>.size
		if pubKeyExists.bool {
			guard count >= MemoryLayout<PublicKey>.size else { return nil }
			self.pubkey = PublicKey(RAW_staticbuff_seeking: &inputPtr)
			dataCount -= MemoryLayout<PublicKey>.size
		} else {
			self.pubkey = nil
		}
		
		guard count >= MemoryLayout<NOSTR_kind>.size + MemoryLayout<Encoded.Bool>.size else { return nil }
		self.kind = NOSTR_kind(RAW_staticbuff_seeking: &inputPtr)
		let dTagExists = Encoded.Bool(RAW_staticbuff_seeking: &inputPtr)
		dataCount -= MemoryLayout<NOSTR_kind>.size + MemoryLayout<Encoded.Bool>.size
		
		if dTagExists.bool {
			let dTagLength = Int(Bytes2(RAW_staticbuff_seeking: &inputPtr).RAW_native())
			dataCount -= MemoryLayout<Bytes2>.size
			guard dataCount == dTagLength else { return nil }
			let dTag = DTag(RAW_decode: inputPtr, count: dTagLength)
			inputPtr = inputPtr.advanced(by: dTagLength)
			dataCount -= dTagLength
			self.dTag = dTag
		} else {
			dTag = nil
		}
		guard dataCount == 0 else { return nil }
	}
	
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<NOSTR_kind>.size + MemoryLayout<Encoded.Bool>.size * 2
		if pubkey != nil {
			count += MemoryLayout<PublicKey>.size
		}
		if dTag != nil {
			count += MemoryLayout<Bytes2>.size
			dTag!.RAW_encode(count: &count)
		}
	}
	
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var dest = dest
		if pubkey != nil {
			dest = Encoded.Bool(true).RAW_encode(dest: dest)
			dest = pubkey!.RAW_encode(dest: dest)
		} else {
			dest = Encoded.Bool(false).RAW_encode(dest: dest)
		}
		
		dest = kind.RAW_encode(dest: dest)
		
		if dTag != nil {
			dest = Encoded.Bool(true).RAW_encode(dest: dest)
			var dTagLength = 0; dTag!.RAW_encode(count: &dTagLength)
			let dTagLengthBytes = Bytes2(RAW_native: UInt16(dTagLength))
			dest = dTagLengthBytes.RAW_encode(dest: dest)
			dest = dTag!.RAW_encode(dest: dest)
		} else {
			dest = Encoded.Bool(false).RAW_encode(dest: dest)
		}
		return dest
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
	
	public static func == (lhs: Self, rhs: Self) -> Bool {
		guard lhs.pubkey == rhs.pubkey,
			  lhs.kind == rhs.kind else {
			return false
		}

		switch (lhs.dTag, rhs.dTag) {
		case (nil, nil):
			return true
		case (nil, _), (_, nil):
			return false
		case let (l?, r?):
			var equal = true
			l.RAW_access { lPtr in
				r.RAW_access { rPtr in
					if lPtr.count != rPtr.count {
						equal = false
						return
					}
					equal = lPtr.elementsEqual(rPtr)
				}
			}
			return equal
		}
	}

	public func hash(into hasher: inout Hasher) {
		hasher.combine(pubkey)
		hasher.combine(kind)

		guard let dTag else {
			hasher.combine(0 as UInt8)
			return
		}
		hasher.combine(1 as UInt8)

		dTag.RAW_access { ptr in
			hasher.combine(ptr.count)
			for byte in ptr {
				hasher.combine(byte)
			}
		}
	}
}
