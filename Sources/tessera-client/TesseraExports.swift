import nostr_kit_swift
import RAW
import RAW_dh25519
import RAW_ed25519
import RAW_base64
import NIO
import Logging

// Tessera client facade.
//
// A client application should depend on nothing but this package's `tessera-client`
// product (declared in Package.swift) and write `import tessera_client`. These
// `@_exported import` lines make the entire tessera public surface visible through
// that single module: `tessera_core` itself (TesseraClient, TesseraSession,
// TesseraModel, TesseraClientReceiverStore, ...) plus the rawdog / swift-nio /
// nostr-kit-swift types those APIs expose (PublicKey, MemoryGuarded,
// RAW_ed25519.PrivateKey, UnsignedEvent, Filter, ByteBuffer, ...). SwiftPM links the transitive products
// automatically, so a client manifest lists only the tessera package.
//
// This file lives in its OWN target (`tessera-client`), NOT in tessera-core:
// `@_exported import` of a rawdog RAW_* module re-exports its top-level name space
// into the hosting module, and rawdog modules each export a top-level `enum Error`
// (plus other generic names such as `Encoded`). Placing the re-exports inside
// tessera-core made tessera-core's own source resolve those names instead of the
// standard library's (e.g. `SignedNoteError : Error` picked up rawdog's `Error` and
// stopped compiling). Isolating the re-exports in a dedicated facade module keeps
// tessera-core's own compilation clean; only the facade (and thus its clients)
// see the re-exported names.
//
// Clients declaring their own error enums must still write `Swift.Error` (rawdog
// re-exports shadow the bare `Error`); tessera's own types do the same.

@_exported import tessera_core
@_exported import nostr_kit_swift
@_exported import RAW_dh25519
@_exported import RAW_ed25519
@_exported import RAW_base64
@_exported import RAW
@_exported import NIO
@_exported import Logging
