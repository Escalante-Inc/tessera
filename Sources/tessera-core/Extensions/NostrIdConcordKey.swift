import RAW
import QuickLMDB
import nostr_kit_swift
import concord

/// Declares `NOSTR_id` as a concord `ConcordKey` so the `SignedEvents` strict
/// database can be reconciled through the concord engine.
///
/// All requirements are already satisfied:
/// - `RAW_staticbuff` — macro-conferred on `NOSTR_id` in nostr-kit-swift.
/// - `MDB_comparable` — retroactive conformance in `Extensions/MdbComparable.swift`.
/// - `Comparable`, `Hashable`, `Sendable` — nostr-kit-swift.
extension NOSTR_id: @retroactive ConcordKey {}
