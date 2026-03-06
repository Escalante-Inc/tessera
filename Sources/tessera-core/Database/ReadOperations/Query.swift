import Logging
import Foundation
import NIO
import RAW
import RAW_dh25519
import bedrock
import QuickLMDB
import nostr_kit_swift

fileprivate func isNewer(_ lhs: TesseraSignedEvent, than rhs: TesseraSignedEvent) -> Bool {
	let l = lhs.unsignedEvent
	let r = rhs.unsignedEvent
	if l.date != r.date {
		return l.date > r.date
	}
	return l.id > r.id
}

internal func isReplaceableKind(_ kind: NOSTR_kind) -> Bool{
	let kindInt = kind.RAW_native()
	return kindInt == 0 || kindInt == 3 || (10_000...19_999).contains(kindInt) || (30_000...39_999).contains(kindInt)
}
internal func isParameterizedReplaceable(_ kind: NOSTR_kind) -> Bool {
	return (30000...39999).contains(kind.RAW_native())
}

extension TesseraDB {
	/// Returns the nostr event for the specified `NOSTR_id`
	public func queryEventID(_ id: NOSTR_id) throws -> TesseraSignedEvent {
		let newTrans = try Transaction(env:env, readOnly:true)
		return try signedEvents.loadEntry(key: id, tx: newTrans)
	}
	
	/// Gets all filter eligible ids.
	/// Returns the tuple containing all filter eligible ids and all author ids.
	public func getFilterEligibleIds(filters:[Filter], tx:borrowing Transaction) throws -> (Set<NOSTR_id>, Set<NOSTR_id>) {
		var allAuthors = Set<NOSTR_id>()
		var allFilterIds = Set<NOSTR_id>()
		for filter in filters {
			var filterIds = Set<NOSTR_id>()
			var ids:Set<NOSTR_id>! = nil
			var kindIds:Set<NOSTR_id>! = nil
			var authorIds:Set<NOSTR_id>! = nil
			var tagIds:Set<NOSTR_id>! = nil
			var dateIds:Set<NOSTR_id>! = nil
			
			if !filter.ids.isEmpty {
				ids = Set<NOSTR_id>(filter.ids)
			}
			
			// Only one author in event, so multiple authors are OR'd (union)
			if !filter.authors.isEmpty {
				authorIds = Set<NOSTR_id>()
				for author in filter.authors {
					do {
						try authorIndex.cursor(tx: tx) { cursor in
							let id = try cursor.opSet(key: author)
							authorIds.insert(id)
							while let id = try? cursor.opNextDup() {
								authorIds.insert(id)
							}
						}
					} catch {}
				}
				allAuthors.formUnion(authorIds)
			}

			// Only one kind in event, so multiple kinds are OR'd (union)
			if !filter.kinds.isEmpty {
				kindIds = Set<NOSTR_id>()
				for kind in filter.kinds {
					do {
						try kindIndex.cursor(tx: tx) { cursor in
							let id = try cursor.opSet(key: kind)
							kindIds.insert(id)
							while let id = try? cursor.opNextDup() {
								kindIds.insert(id)
							}
						}
					} catch {}
				}
			}
			
			// Multiple tags in one event, so multiple tags are AND'd (intersection)
			if !filter.tags.isEmpty {
				do {
					var iterator = filter.tags.makeIterator()
					if let firstTag = iterator.next() {
						tagIds = Set<NOSTR_id>()
						try tagIndex.cursor(tx: tx) { cursor in
							let id = try cursor.opSet(key: firstTag as! EventTag)
							tagIds.insert(id)
							while let id = try? cursor.opNextDup() {
								tagIds.insert(id)
							}
						}
						while let tag = iterator.next() {
							var newTagIds = Set<NOSTR_id>()
							try tagIndex.cursor(tx: tx) { cursor in
								let id = try cursor.opSet(key: tag as! EventTag)
								newTagIds.insert(id)
								while let id = try? cursor.opNextDup() {
									newTagIds.insert(id)
								}
							}
							tagIds.formIntersection(newTagIds)
						}
					}
				} catch {
					tagIds = []
					break
				}
			}
			
			// Events gathered for: since < creation date < until
			if filter.since != nil || filter.until != nil {
				dateIds = Set<NOSTR_id>()
				do {
					try dateIndex.cursor(tx: tx) { cursor in
						if let since = filter.since {
							_ = try cursor.opSetRange(key: since)
						} else {
							_ = try cursor.opFirst()
						}
						if let until = filter.until {
							let (key, val) = try cursor.opGetCurrent()
							if key < until {
								dateIds.insert(val)
							}
							while let (key, val) = try? cursor.opNext() {
								if key < until {
									dateIds.insert(val)
								}
							}
						} else {
							let (_, val) = try cursor.opGetCurrent()
							dateIds.insert(val)
							while let (_, val) = try? cursor.opNext() {
								dateIds.insert(val)
							}
						}
					}
				} catch {
					dateIds = nil
				}
			}
			
			let sets: [Set<NOSTR_id>] = [ids, kindIds, authorIds, tagIds, dateIds].compactMap { $0 }
			if let first = sets.first {
				filterIds = first
				for set in sets.dropFirst() {
					filterIds.formIntersection(set)
				}
			} else {
				filterIds = []
			}
			
			allFilterIds.formUnion(filterIds)
		}
		return (allFilterIds, allAuthors)
	}
	
	/// Filters out all events from the database that match the given filters.
	/// Follows the NOSTR protocol where the filters use an OR function and each filter's fields use an AND function.
	/// Thus, a signed event only needs to match all of the constraints of a single filter to be returned.
	///
	/// Uses a 'dumb' filter. Ignores deletions or updates on events.
	public func queryEventsByDumbFilter(filters:[Filter]) throws -> [TesseraSignedEvent] {
		let newTrans = try Transaction(env:env, readOnly:true)
		let (allFilterIds, _) = try getFilterEligibleIds(filters: filters, tx: newTrans)
		guard !allFilterIds.isEmpty else {
			return []
		}
		var queriedEvents:[TesseraSignedEvent] = []
		try signedEvents.cursor(tx:newTrans) { cursor in
			for id in allFilterIds {
				queriedEvents.append(try cursor.opSet(key: id))
			}
		}
		return queriedEvents
	}
	
	/// Filters out all events from the database that match the given filters.
	/// Follows the NOSTR protocol where the filters use an OR function and each filter's fields use an AND function.
	/// Thus, a signed event only needs to match all of the constraints of a single filter to be returned.
	///
	/// Uses a 'smart' filter. Respects deletions and updates on events.
	public func queryEventsBySmartFilter(filters:[Filter]) throws -> [TesseraSignedEvent] {
		let newTrans = try Transaction(env:env, readOnly:true)
		var (allFilterIds, allAuthors) = try getFilterEligibleIds(filters: filters, tx: newTrans)
		guard !allFilterIds.isEmpty else {
			return []
		}
		// Now have all filtered ids. Still would need to clean deleted events and updated events.
		// Removing ids for deleted events
		do {
			var kind5Ids = Set<NOSTR_id>()
			try kindIndex.cursor(tx: newTrans) { cursor in
				let id = try cursor.opSet(key: NOSTR_kind(RAW_native: 5))
				kind5Ids.insert(id)
				while let id = try? cursor.opNextDup() {
					kind5Ids.insert(id)
				}
			}
			
			if !allAuthors.isEmpty { kind5Ids.formIntersection(allAuthors) }
			var deleteIds = Set<NOSTR_id>()
			try signedEvents.cursor(tx:newTrans) { cursor in
				for id in kind5Ids {
					let signedEvent = try cursor.opSet(key: id)
					for tag in signedEvent.unsignedEvent.tags.array {
						guard tag.NOSTR_tag_index_field == NOSTR_tag_name(string: "e") else {
							continue
						}
						deleteIds.insert(NOSTR_id(tagValue: tag.NOSTR_tag_values.array.first! as! NOSTR_tag_generic_value)!)
					}
				}
			}
			allFilterIds.subtract(deleteIds)
			allFilterIds.subtract(kind5Ids)
		} catch {}
		
		// Now get the signed events for all remaining ids.
		// Then need to filter out old events for any updated events.
		var queriedEvents:[TesseraSignedEvent] = []
		try signedEvents.cursor(tx:newTrans) { cursor in
			for id in allFilterIds {
				queriedEvents.append(try cursor.opSet(key: id))
			}
		}
		
		var upToDateEvents: [TesseraSignedEvent] = []
		
		for signedEvent in queriedEvents {
			let unsigned = signedEvent.unsignedEvent
			let kind = unsigned.kind
			let pubkey = unsigned.publicKey
			
			if !isReplaceableKind(kind) {
				upToDateEvents.append(signedEvent)
				continue
			}
			
			let dTag: (any NOSTR_tag_value)?
			if isParameterizedReplaceable(kind) {
				guard let tag = unsigned.tags.array.first(where: { $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "d") }) else {
					throw SignedNoteError.invalidParameterizedEvent
				}
				dTag = tag.NOSTR_tag_values.array.first!
			} else {
				dTag = nil
			}
			
			let key = ReplaceableKey(pubkey: pubkey, kind: kind, dTag: dTag)
			
			try replaceableEvents.cursor(tx: newTrans) { cursor in
				_ = try cursor.opSet(key: key)
				if try cursor.opLastDup().id == signedEvent.unsignedEvent.id {
					upToDateEvents.append(signedEvent)
				}
			}
		}
		
		if let limit = filters.first?.limit?.RAW_native() {
			return Array(upToDateEvents.sorted { $0.unsignedEvent.date > $1.unsignedEvent.date }.prefix(Int(limit)))
		}
		
		return upToDateEvents
	}
}
