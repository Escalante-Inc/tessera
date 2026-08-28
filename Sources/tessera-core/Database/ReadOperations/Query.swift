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
			var applicationIds:Set<NOSTR_id>! = nil
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
							// Guard with containsEntry first: opSet throws (and fatals via the
							// RAW_access `try!`) when the key isn't present in the index.
							guard try cursor.containsEntry(key: author) else { return }
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
							guard try cursor.containsEntry(key: kind) else { return }
							let id = try cursor.opSet(key: kind)
							kindIds.insert(id)
							while let id = try? cursor.opNextDup() {
								kindIds.insert(id)
							}
						}
					} catch {}
				}
			}
			
			// Only one application in event, so multiple applications are OR'd (union)
			if !filter.applications.isEmpty {
				applicationIds = Set<NOSTR_id>()
				for application in filter.applications {
					do {
						try applicationIndex.cursor(tx: tx) { cursor in
							guard try cursor.containsEntry(key: application) else { return }
							let id = try cursor.opSet(key: application)
							applicationIds.insert(id)
							while let id = try? cursor.opNextDup() {
								applicationIds.insert(id)
							}
						}
					} catch {}
				}
			}
			
			// Multiple tags in one event, so multiple tags are AND'd (intersection)
			if !filter.tags.isEmpty {
				// Only tags that can be represented as an `EventTag` are stored in the tag index.
				// Any other tag type can never match an indexed event, so treat it as an empty
				// constraint (yields nothing) rather than force-casting and crashing.
				let eventTags = filter.tags.compactMap { $0 as? EventTag }
				if eventTags.isEmpty {
					tagIds = []
				} else {
					do {
						var iterator = eventTags.makeIterator()
						if let firstTag = iterator.next() {
							tagIds = Set<NOSTR_id>()
							try tagIndex.cursor(tx: tx) { cursor in
								guard try cursor.containsEntry(key: firstTag) else { return }
								let id = try cursor.opSet(key: firstTag)
								tagIds.insert(id)
								while let id = try? cursor.opNextDup() {
									tagIds.insert(id)
								}
							}
							while let tag = iterator.next() {
								var newTagIds = Set<NOSTR_id>()
								try tagIndex.cursor(tx: tx) { cursor in
									guard try cursor.containsEntry(key: tag) else {
										newTagIds = []
										return
									}
									let id = try cursor.opSet(key: tag)
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
			}
			
			// Events gathered for: since <= creation date <= until
			if filter.since != nil || filter.until != nil {
				dateIds = Set<NOSTR_id>()
				do {
					try dateIndex.cursor(tx: tx) { cursor in
						// The date index is sorted ascending by `NOSTR_date`. Iterate it in order,
						// collecting ids whose date falls within [since, until]. Both bounds are
						// inclusive, matching NIP-01 and `applyTesseraFilter`. `opFirst`/`opNext`
						// return a catchable `notFound` at the boundaries (unlike `opSet`/`opSetRange`,
						// which fatal the process via a `RAW_access` `try!` when a key is absent).
						let since = filter.since ?? NOSTR_date(date: Date(timeIntervalSince1970: 0))
						var (key, val) = try cursor.opFirst()
						if key >= since && (filter.until == nil || key <= filter.until!) {
							dateIds.insert(val)
						}
						while let (nextKey, nextVal) = try? cursor.opNext() {
							key = nextKey
							val = nextVal
							if let until = filter.until, key > until {
								break
							}
							if key >= since {
								dateIds.insert(val)
							}
						}
					}
				} catch {
					// No events fall within the requested date range, or the range is invalid.
					// Keep the date constraint (empty set) so the query yields no results rather
					// than silently dropping the date bounds and returning unrelated events.
					dateIds = []
				}
			}
			
			let sets: [Set<NOSTR_id>] = [ids, applicationIds, kindIds, authorIds, tagIds, dateIds].compactMap { $0 }
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
	public func queryEventsByDumbFilter(filters:[Filter], user: PublicKey? = nil) throws -> [TesseraSignedEvent] {
		let newTrans = try Transaction(env:env, readOnly:true)
		var (allFilterIds, allAuthors) = try getFilterEligibleIds(filters: filters, tx: newTrans)
		guard !allFilterIds.isEmpty else {
			return []
		}
		// Removing ids for deleted events
		do {
			var kind5Ids = Set<NOSTR_id>()
			try kindIndex.cursor(tx: newTrans) { cursor in
				// Kind-5 (deletion) events may not exist in the index; guard before opSet.
				guard try cursor.containsEntry(key: NOSTR_kind(RAW_native: 5)) else { return }
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
						guard let eventRefTag = tag.unwrap(as: EventRefTag.self) else {
							continue
						}
						deleteIds.insert(eventRefTag.value)
					}
				}
			}
			allFilterIds.subtract(deleteIds)
			allFilterIds.subtract(kind5Ids)
		} catch {}
		
		var queriedEvents:[TesseraSignedEvent] = []
		try signedEvents.cursor(tx:newTrans) { cursor in
			for id in allFilterIds {
				// `filter.ids` are vetted against the index DBs below, but the ids field itself
				// is taken verbatim from the filter and may reference events that were never
				// stored (or were force-deleted). Guard before `opSet` so a single stale id can't
				// abort the whole query (NIP-01: missing ids are simply skipped).
				guard try cursor.containsEntry(key: id) else { continue }
				queriedEvents.append(try cursor.opSet(key: id))
			}
		}
		if let limit = filters.first?.limit?.RAW_native() {
			queriedEvents = Array(queriedEvents.sorted { $0.unsignedEvent.date > $1.unsignedEvent.date }.prefix(Int(limit)))
		}
		if let user = user {
			let uniqueKinds = Array(Set(queriedEvents.map { $0.unsignedEvent.kind }))
			guard try checkReadAccess(user: user, kinds: uniqueKinds, tx: newTrans) else {
				throw AccessLevelError.invalidReadAccess
			}
		}
		return queriedEvents
	}

	/// Filters out all events from the database that match the given filters.
	/// Follows the NOSTR protocol where the filters use an OR function and each filter's fields use an AND function.
	/// Thus, a signed event only needs to match all of the constraints of a single filter to be returned.
	///
	/// Uses a 'smart' filter. Respects deletions and updates on events.
	public func queryEventsBySmartFilter(filters:[Filter], user: PublicKey? = nil) throws -> [TesseraSignedEvent] {
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
				// Kind-5 (deletion) events may not exist in the index; guard before opSet.
				guard try cursor.containsEntry(key: NOSTR_kind(RAW_native: 5)) else { return }
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
						guard let eventRefTag = tag.unwrap(as: EventRefTag.self) else {
							continue
						}
						deleteIds.insert(eventRefTag.value)
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
				// `filter.ids` may reference events that were never stored or were force-deleted;
				// skip such ids rather than letting a single stale id abort the whole query.
				guard try cursor.containsEntry(key: id) else { continue }
				queriedEvents.append(try cursor.opSet(key: id))
			}
		}
		
		var upToDateEvents: [TesseraSignedEvent] = []
		
		for signedEvent in queriedEvents {
			let unsignedEvent = signedEvent.unsignedEvent
			let kindInt = unsignedEvent.kind.RAW_native() % 40_000
			
			if NostrKindCategory.nonReplaceable.range.contains(kindInt) {
				upToDateEvents.append(signedEvent)
				continue
			}
			
			let key = try ReplaceableKey(event: unsignedEvent)
			
			try replaceableEvents.cursor(tx: newTrans) { cursor in
				// The replaceable key may not exist (e.g. it was force-deleted); guard before opSet.
				guard try cursor.containsEntry(key: key) else { return }
				_ = try cursor.opSet(key: key)
				if try cursor.opLastDup().id == signedEvent.unsignedEvent.id {
					upToDateEvents.append(signedEvent)
				}
			}
		}
		
		if let limit = filters.first?.limit?.RAW_native() {
			upToDateEvents = Array(upToDateEvents.sorted { $0.unsignedEvent.date > $1.unsignedEvent.date }.prefix(Int(limit)))
		}
		
		if let user = user {
			let uniqueKinds = Array(Set(upToDateEvents.map { $0.unsignedEvent.kind }))
			guard try checkReadAccess(user: user, kinds: uniqueKinds, tx: newTrans) else {
				throw AccessLevelError.invalidReadAccess
			}
		}
		
		return upToDateEvents
	}
}
