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
fileprivate func isParameterizedReplaceable(_ kind: NOSTR_kind) -> Bool {
	return (30000...39999).contains(kind.RAW_native())
}

extension TesseraDB {
	/// Returns the nostr event for the specified `NOSTR_id`
	public func queryEventID(_ id: NOSTR_id) throws -> TesseraSignedEvent {
		let newTrans = try Transaction(env:env, readOnly:true)
		return try signedEvents.loadEntry(key: id, tx: newTrans)
	}
	
	/// Filters out all events from the database that match the given filters.
	/// Follows the NOSTR protocol where the filters use an OR function and each filter's fields use an AND function.
	/// Thus, a signed event only needs to match all of the constraints of a single filter to be returned.
	///
	/// Uses a 'dumb' filter. Ignores deletions or updates on events.
	/// Time complexity: O(n) where n is the number of signed events.
	public func queryEventsByFilter(filter:[Filter]) throws -> [TesseraSignedEvent] {
		var filteredEvents:[TesseraSignedEvent] = []
		// Filters are OR'd and filter fields are AND'ed
		let newTrans = try Transaction(env:env, readOnly:true)
		do {
			try signedEvents.cursor(tx:newTrans) { cursor in
				let (_, val) = try cursor.opFirst()
				if eventMatchesFilters(val, filters: filter, logLevel: log.logLevel) {
					filteredEvents.append(val)
				}
				while let (_, val) = try? cursor.opNext() {
					if eventMatchesFilters(val, filters: filter, logLevel: log.logLevel) {
						filteredEvents.append(val)
					}
				}
			}
		} catch { }
		log.debug(Logger.Message.green("successfully queried \(filteredEvents.count) events that match the given filters"))
		return filteredEvents
	}
	
	public func queryEventsBySmartFilter(filters:[Filter]) throws -> [TesseraSignedEvent] {
		let newTrans = try Transaction(env:env, readOnly:true)
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
						authorIds.formUnion(try authorIndex.loadEntry(key: author, tx: newTrans).ids)
					} catch {}
				}
				allAuthors.formUnion(authorIds)
			}

			// Only one kind in event, so multiple kinds are OR'd (union)
			if !filter.kinds.isEmpty {
				kindIds = Set<NOSTR_id>()
				for kind in filter.kinds {
					do {
						kindIds.formUnion(try kindIndex.loadEntry(key: kind, tx: newTrans).ids)
					} catch {}
				}
			}
			
			// Multiple tags in one event, so multiple tags are AND'd (intersection)
			if !filter.tags.isEmpty {
				do {
					var iterator = filter.tags.makeIterator()
					if let firstTag = iterator.next() {
						tagIds = try tagIndex.loadEntry(key: firstTag as! EventTag, tx: newTrans).ids
						while let tag = iterator.next() {
							tagIds.formIntersection(try tagIndex.loadEntry(key: tag as! EventTag, tx: newTrans).ids)
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
					try dateIndex.cursor(tx: newTrans) { cursor in
						if let since = filter.since {
							_ = try cursor.opSetRange(key: since)
						} else {
							_ = try cursor.opFirst()
						}
						if let until = filter.until {
							let (key, val) = try cursor.opGetCurrent()
							if key < until {
								dateIds.formUnion(val.ids)
							}
							while let (key, val) = try? cursor.opNext() {
								if key < until {
									dateIds.formUnion(val.ids)
								}
							}
						} else {
							let (_, val) = try cursor.opGetCurrent()
							dateIds.formUnion(val.ids)
							while let (_, val) = try? cursor.opNext() {
								dateIds.formUnion(val.ids)
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
		guard !allFilterIds.isEmpty else {
			return []
		}
		// Now have all filtered ids. Still would need to clean deleted events and updated events.
		// Removing ids for deleted events
		do {
			var kind5Ids = try kindIndex.loadEntry(key: NOSTR_kind(RAW_native: 5), tx: newTrans).ids
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
			
			if try replaceableEvents.loadEntry(key: key, tx: newTrans).ids.first! == signedEvent.unsignedEvent.id {
				upToDateEvents.append(signedEvent)
			}
		}
		
		if let limit = filters.first?.limit?.RAW_native() {
			return Array(upToDateEvents.sorted { $0.unsignedEvent.date > $1.unsignedEvent.date }.prefix(Int(limit)))
		}
		
		return upToDateEvents
	}
}
