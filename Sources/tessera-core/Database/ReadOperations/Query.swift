import Logging
import Foundation
import NIO
import RAW
import RAW_dh25519
import bedrock
import QuickLMDB
import nostr_kit_swift

extension TesseraDB {
	/// Returns the nostr event for the specified `NOSTR_id`
	public func queryEventID(_ id: NOSTR_id) throws -> StoredSignedEvent {
		let newTrans = try Transaction(env:env, readOnly:true)
		return try signedEvents.loadEntry(key: id, tx: newTrans)
	}
	
	/// Filters out all events from the database that match the given filters.
	/// Follows the NOSTR protocol where the filters use an OR function and each filter's fields use an AND function.
	/// Thus, a signed event only needs to match all of the constraints of a single filter to be returned.
	///
	/// Uses a 'dumb' filter. Ignores deletions or updates on events.
	/// Time complexity: O(n) where n is the number of signed events.
	public func queryEventsByFilter(filter:[Filter]) throws -> [StoredSignedEvent] {
		var filteredEvents:[StoredSignedEvent] = []
		// Filters are OR'd and filter fields are AND'ed
		let newTrans = try Transaction(env:env, readOnly:true)
		do {
			try signedEvents.cursor(tx:newTrans) { cursor in
				let (_, val) = try cursor.opFirst()
				if eventMatchesFilters(val.event, filters: filter, logLevel: log.logLevel) {
					filteredEvents.append(val)
				}
				while let (_, val) = try? cursor.opNext() {
					if eventMatchesFilters(val.event, filters: filter, logLevel: log.logLevel) {
						filteredEvents.append(val)
					}
				}
			}
		} catch { }
		log.debug(Logger.Message.green("successfully queried \(filteredEvents.count) events that match the given filters"))
		return filteredEvents
	}
}
