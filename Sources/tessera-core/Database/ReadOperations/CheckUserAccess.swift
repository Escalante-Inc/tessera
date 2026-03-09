import QuickLMDB
import RAW_dh25519
import nostr_kit_swift

func rangeIndex(for value: Int) -> Int {
	let start = 40_000; let width = 40_000
	let index = (value - start) / width
	guard index < 256 else { return -1 }
	return index
}

extension TesseraDB {
	/// Takes in a user as a `PublicKey` and the kinds that the user wants a read access check on as a `[NOSTR_kind]`
	/// Returns the read access allowed kinds as an `[NOSTR_kind]`
	func checkReadAccessForgiving(user: PublicKey, kinds: [NOSTR_kind], tx: borrowing Transaction) throws -> [NOSTR_kind] {
		let userEventId = try userIndex.loadEntry(key: user, tx: tx)
		let userEvent = try signedEvents.loadEntry(key: userEventId, tx: tx)
		guard let userAccess = userEvent.unsignedEvent.tags.array.first(where: { $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "readAccessLevels")})?.NOSTR_tag_values.array.first else {
			throw AccessLevelError.userHasNoAccessLevels
		}
		return userAccess.RAW_access { ptr in
			var allowedKinds:[NOSTR_kind] = []
			for kind in kinds {
				guard kind.RAW_native() >= 40_000 else { allowedKinds.append(kind); continue }
				let index = rangeIndex(for: Int(kind.RAW_native()))
				let byteIndex = index / 8
				let bitIndex  = index % 8
				let byte = ptr[byteIndex]
				if (byte & (1 << bitIndex)) == 1 {
					allowedKinds.append(kind)
				}
			}
			return allowedKinds
		}
	}
	
	/// Takes in a user as a `PublicKey` and the kinds that the user wants a read access check on as a `[NOSTR_kind]`
	/// Returns a Bool. If false, then one or more kinds failed the access check.
	func checkReadAccess(user: PublicKey, kinds: [NOSTR_kind], tx: borrowing Transaction) throws -> Bool {
		let userEventId = try userIndex.loadEntry(key: user, tx: tx)
		let userEvent = try signedEvents.loadEntry(key: userEventId, tx: tx)
		guard let userAccess = userEvent.unsignedEvent.tags.array.first(where: { $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "readAccessLevels")})?.NOSTR_tag_values.array.first else {
			throw AccessLevelError.userHasNoAccessLevels
		}
		return userAccess.RAW_access { ptr in
			for kind in kinds {
				guard kind.RAW_native() >= 40_000 else { continue }
				let index = rangeIndex(for: Int(kind.RAW_native()))
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
	func checkWriteAccess(user: PublicKey, kind: NOSTR_kind, tx: borrowing Transaction) throws -> Bool {
		let userEventId = try userIndex.loadEntry(key: user, tx: tx)
		let userEvent = try signedEvents.loadEntry(key: userEventId, tx: tx)
		guard let userAccess = userEvent.unsignedEvent.tags.array.first(where: { $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "writeAccessLevels")})?.NOSTR_tag_values.array.first else {
			throw AccessLevelError.userHasNoAccessLevels
		}
		return userAccess.RAW_access { ptr in
			guard kind.RAW_native() >= 40_000 else { return true }
			let index = rangeIndex(for: Int(kind.RAW_native()))
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
