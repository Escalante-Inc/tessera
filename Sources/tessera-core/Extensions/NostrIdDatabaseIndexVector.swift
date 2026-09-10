import Foundation
import RAW
import QuickLMDB
import nostr_kit_swift
import negentropy_swift

/// Declares `NOSTR_id` as a negentropy `DatabaseIndexVector` so that the
/// `signedEvents` strict database can be handed to the negentropy sync engine.
///
/// `DatabaseIndexVector` requires `RAW_staticbuff` (macro-conferred on
/// `NOSTR_id`), `MDB_comparable` (conferred in `MdbComparable.swift`), and the
/// value-type protocols (`Equatable`, `Comparable`, `Hashable`). Swift will not
/// derive this two-level conditional conformance on its own, so it is declared
/// explicitly here. This conformance lives in tessera (not a fork of negentropy
/// or nostr-kit), keeping all sync logic within this project.
///
/// - warning: Declares an external conformance; if `nostr-kit-swift` ever adds
///   this conformance upstream, remove this declaration.
extension NOSTR_id: @retroactive DatabaseIndexVector {}
