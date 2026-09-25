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
	func checkReadAccessForgiving<M: TransactionMode>(user: PublicKey, kinds: [NOSTR_kind], tx: borrowing Transaction<M>) throws -> [NOSTR_kind] {
		let userEventId = try userIndex.loadEntry(key: user, tx: tx)
		let userEvent = try signedEvents.loadEntry(key: userEventId, tx: tx)
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
	func checkReadAccess<M: TransactionMode>(user: PublicKey, kinds: [NOSTR_kind], tx: borrowing Transaction<M>) throws -> Bool {
		let userEventId = try userIndex.loadEntry(key: user, tx: tx)
		let userEvent = try signedEvents.loadEntry(key: userEventId, tx: tx)
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
	func checkWriteAccess<M: TransactionMode>(user: PublicKey, kind: NOSTR_kind, tx: borrowing Transaction<M>) throws -> Bool {
		let userEventId = try userIndex.loadEntry(key: user, tx: tx)
		let userEvent = try signedEvents.loadEntry(key: userEventId, tx: tx)
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
