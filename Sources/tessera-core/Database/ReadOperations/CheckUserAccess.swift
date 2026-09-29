import QuickLMDB
import RAW_dh25519
import nostr_kit_swift

func rangeIndex(for value: Int) -> Int? {
	let start = 40_000; let width = 40_000
	guard value >= start else { return nil }
	let index = (value - start) / width
	guard index < 256 else { return nil }
	return index
}

extension TesseraDB {
	/// Takes in a user as a `PublicKey` and the kinds that the user wants a read access check on as a `[NOSTR_kind]`
	/// Returns the read access allowed kinds as an `[NOSTR_kind]`
	@MDB_transact(.readOnly)
	func checkReadAccessForgiving(user: PublicKey, kinds: [NOSTR_kind]) throws -> [NOSTR_kind] {
		let userEventId = #load(TesseraDB.self, database: \.userIndex, key: user)
		guard let userEventId = userEventId else { throw LMDBError.notFound }
		guard let userEvent = #load(TesseraDB.self, database: \.signedEvents, key: userEventId) else { throw LMDBError.notFound }
		guard let userAccessTag = findTag(tags: userEvent.unsignedEvent.tags.array, as: ReadAccessLevels.self) else {
			throw AccessLevelError.userHasNoAccessLevels
		}
		let userAccess = userAccessTag.value
		return userAccess.RAW_access_immutable(UnsafeBufferPointer<UInt8>.self) { ptr in
			var allowedKinds:[NOSTR_kind] = []
			for kind in kinds {
				guard kind.RAW_native() >= 40_000 else { allowedKinds.append(kind); continue }
				guard let index = rangeIndex(for: Int(kind.RAW_native())) else { continue }
				let byteIndex = index / 8
				let bitIndex  = index % 8
				let byte = ptr[byteIndex]
				if (byte & (1 << bitIndex)) != 0 {
					allowedKinds.append(kind)
				}
			}
			return allowedKinds
		}
	}
	
	/// Takes in a user as a `PublicKey` and the kinds that the user wants a read access check on as a `[NOSTR_kind]`
	/// Returns a Bool. If false, then one or more kinds failed the access check.
	@MDB_transact(.readOnly)
	func checkReadAccess(user: PublicKey, kinds: [NOSTR_kind]) throws -> Bool {
		guard let userEventId = #load(TesseraDB.self, database: \.userIndex, key: user) else { throw LMDBError.notFound }
		guard let userEvent = #load(TesseraDB.self, database: \.signedEvents, key: userEventId) else { throw LMDBError.notFound }
		guard let userAccessTag = findTag(tags: userEvent.unsignedEvent.tags.array, as: ReadAccessLevels.self) else {
			throw AccessLevelError.userHasNoAccessLevels
		}
		let userAccess = userAccessTag.value
		return userAccess.RAW_access_immutable(UnsafeBufferPointer<UInt8>.self) { ptr in
			for kind in kinds {
				guard kind.RAW_native() >= 40_000 else { continue }
				guard let index = rangeIndex(for: Int(kind.RAW_native())) else { return false }
				let byteIndex = index / 8
				let bitIndex  = index % 8
				let byte = ptr[byteIndex]
				if (byte & (1 << bitIndex)) == 0 {
					return false
				}
			}
			return true
		}
	}
	
	/// Takes in a user as a `PublicKey` and the kind that the user wants a write access check on as a `[NOSTR_kind]`
	/// Returns a Bool indicating write access.
	@MDB_transact(.readOnly)
	func checkWriteAccess(user: PublicKey, kind: NOSTR_kind) throws -> Bool {
		guard let userEventId = #load(TesseraDB.self, database: \.userIndex, key: user) else { throw LMDBError.notFound }
		guard let userEvent = #load(TesseraDB.self, database: \.signedEvents, key: userEventId) else { throw LMDBError.notFound }
		guard let userAccessTag = findTag(tags: userEvent.unsignedEvent.tags.array, as: WriteAccessLevels.self) else {
			throw AccessLevelError.userHasNoAccessLevels
		}
		let userAccess = userAccessTag.value
		return userAccess.RAW_access_immutable(UnsafeBufferPointer<UInt8>.self) { ptr in
			guard kind.RAW_native() >= 40_000 else { return true }
			guard let index = rangeIndex(for: Int(kind.RAW_native())) else { return false }
			let byteIndex = index / 8
			let bitIndex  = index % 8
			let byte = ptr[byteIndex]
			if (byte & (1 << bitIndex)) == 0 {
				return false
			}
			return true
		}
	}
}
