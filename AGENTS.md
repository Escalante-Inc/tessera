# AGENTS.md

Guidance for AI agents working in the **tessera** repository. Read this before editing code.

## What this project is

Tessera is a macOS-only Swift package that ships a single executable acting as **both a long-running daemon server and a CLI tool** for a calendar/event application. The daemon acts as a connection point for other tessera nodes and end-user applications: it listens on a WireGuard interface, receives signed events and requests, stores them in a local LMDB database, and serves/fans them out to subscribers. The CLI manages the daemon, users, access levels, and WireGuard peer configuration.

Key traits:
- Built with **Swift 6.2**, platform `.macOS(.v15)` (requires Apple Silicon or at least macOS 15; relies on local path dependencies and a SmartCard code-sign entitlement).
- Storage is **LMDB** via `QuickLMDB`. Events are **signed NOSTR events**, serialized with the **RAW** library (`rawdog`).
- Everything funnels through a `NOSTR_event_signed<UnsignedEvent<ByteBuffer>>` (`typealias TesseraSignedEvent`).

## Module / target layout

- **`tessera`** — executable target. CLI (`Sources/tessera/CLI/`) and the daemon service (`Sources/tessera/Service/`).
- **`tessera-core`** — library target. The database layer and client-side model layer. Depends on `nostr-kit-swift`, `bedrock`, `RAW`, `QuickLMDB`, `NIO`. This is the re-usable core.
- **`tessera-tests`** — test target against `tessera-core`.

### Sources/tessera (executable)
- `CLI/Run.swift` — `@main struct CLI: AsyncParsableCommand`, command name `tessera-service`. Subcommands: `Run`, `GenerateKeys`, `GenerateEd25519Keys`, `CreateNewAccessLevel`, `CreateUser`, `CreateUnboundedAdmin`, `CreateUnboundedYubikeyAdmin`, `Config`.
  - **`Run`** starts the daemon: builds `TesseraService` and runs it in a `ServiceGroup` from `swift-service-lifecycle`.
  - `CreateUser` / `CreateUnboundedAdmin` / `CreateUnboundedYubikeyAdmin` / `CreateNewAccessLevel` require a plugged-in **YubiKey** (OpenPGP smartcard) or a secret key, and write a signed event into the DB.
- `CLI/WireguardConfiguration.swift` — the `Config` subcommand + JSON peer-config file handling (`WireguardConfig`, `PeerInfo`, `loadConfig`/`writeConfig`/`editConfig`). Config file is `peer-config.json` in the config dir.
- `CLI/Arguments.swift` — `ExpressibleByArgument` extensions for `PublicKey` / `MemoryGuarded<PrivateKey>` (base64 decode) and `Path`.
- `Service/Service.swift` — **`TesseraService: Service`** — the daemon. Runs one WireGuard interface (`WGInterface<KCPChannels>`, mtu 1400) on `myPort`; one task per configured peer that decodes incoming data as NOSTR `EVENT`/`REQ`/`CLOSE` messages, scribes events, answers `REQ` with matching events + `EOSE`, tracks active subscriptions in the `NostrRequestsStore` actor, and fans out new events to matching live subscriptions.
- `SmartCard.entitlements` — `com.apple.security.smartcard = true`; applied by `build.sh`.

### Sources/tessera-core/Database
- `TesseraDB.swift` — the LMDB environment. `TesseraDB(base:memoryMapSize:logLevel:)` creates `tessera.mdb` under `base` and **8 databases**:
  - `SignedEvents` (Strict, `NOSTR_id` → `TesseraSignedEvent`) — the primary store.
  - Indexes (`DupSort`): `AuthorIndex`, `ApplicationIndex`, `KindIndex`, `DateIndex`, `TagIndex` (key → `NOSTR_id`).
  - `UserIndex` (Strict, `PublicKey` → `NOSTR_id`) — maps user pubkey to their kind-0 profile event id.
  - `ReplaceableEvents` (DupSort, `ReplaceableKey` → `DatedID`) — used to resolve the latest revision of replaceable events.
  - `deleteEnvironment(base:environment:logLevel:)` removes the `.mdb` + `.mdb-lock` files.
- `WriteOperations/` — `scribeNewEvent` (validates write access, rejects ephemeral, handles kind-5 deletions, writes event + all indexes), `scribeNewUser`, `forceDeleteEvent(_Filtered)`, `clearEventsDatabase`.
- `ReadOperations/` — `queryEventsBySmartFilter` (respects deletions & updates) and `queryEventsByDumbFilter` (raw). `getFilterEligibleIds` intersects within a filter's fields (AND) and unions across filters (OR). `Stats.swift` (`eventCount`). `CheckUserAccess.swift` (read/write access checks).
- `SupportingFunctions.swift` — `createKind(accessLevel:kind:)`, `applyTesseraFilter`, `eventMatchesFilters`.
- `Structs/` — `User` (kind-0 content), `TesseraKinds` (reserved kinds: user=0, accessLevel=1), `Indexing/` (`ReplaceableKey`, `DatedID`, `NostrKindCategory`), `Error/` (`SignedNoteError`, `AccessLevelError`).

### Sources/tessera-core/ClientReceiver
- `TesseraCompliantModel.swift` — protocol + extension for client-side caching models that converse with a tessera (storage + replaceable-key/history indexes + upsert/delete logic).
- `CleintReceiver.swift` — `TesseraClientReceiver` protocol + extension (decode NOSTR EVENT messages, handle deletions, route to models, track reference needs).

### Tests
- `Tests/tessera-tests/tests.swift` — database tests (smart filter, write/read permissions, deletion, large-data) and encode/decode tests.

## Build / test / run

```bash
swift build                      # compile (debug)
swift test                       # run all tests (Swift Testing)
./build.sh                       # build, then re-sign with SmartCard.entitlements
```

- `build.sh` exists because the binary must be **re-signed with the SmartCard entitlement** for YubiKey/OpenPGP access. For anything touching smartcards, use `build.sh`, not a plain `swift build`/`run`.
- Default DB path: `~/tessera_lmdb` (see `CLI.defaultDBBasePath()`). Default config dir: home dir.
- Test suites open/delete the DB at the **home directory** (`~/tessera.mdb`, `~/tessera.mdb-lock`); `deinit` removes it.
- **Tests use the Swift Testing framework** (`import Testing`, `@Suite`, `@Test`, `#expect`). Never write XCTest.

## Critical domain rules (encode these in any new code)

### Access levels & kind encoding
- There are **256 access levels** (0–255). Each access level owns a contiguous block of **40,000 kinds**: level N owns `[(N+1)*40_000, (N+2)*40_000)`.
- Helper: `createKind(accessLevel:kind:)` = `(accessLevel + 1) * 40_000 + (kind % 40_000)`.
- A user's permitted access levels are stored as a **32-byte bit array** (`UserAccessLevel`, 256 bits) in their kind-0 profile event tags: `readAL` (`ReadAccessLevels`) and `writeAL` (`WriteAccessLevels`).
- Access checks (`checkReadAccess` / `checkWriteAccess`) index into that bit array by `rangeIndex(for:)` and reject kinds `< 40_000` only for writes when there's no mapping. Kind-0 profile/user events are exempt (they're the basis of access).
- `AccessLevelError`: `userDoesNotExist`, `userHasNoAccessLevels`, `invalidReadAccess`, `invalidWriteAccess`.

### NOSTR kind categories (within each access-level block)
Inside each 40k block, `NostrKindCategory` classifies `kind % 40_000`:
- `[0, 10_000)` non-replaceable
- `[10_000, 15_000)` replaceable by `(publicKey, kind)` (`replaceablePK`)
- `[15_000, 25_000)` replaceable by `(kind, d-tag)` (`replaceablePKDTag`)
- `[25_000, 30_000)` ephemeral (never stored — `scribeNewEvent` throws `SignedNoteError.cantStoreEphemeralEvent`)
- `[30_000, 40_000)` replaceable by `(publicKey, kind, d-tag)` (`replaceablePKKindDTag`)

### Replaceable / deletion semantics
- Non-replaceable kinds are stored once. Replaceable kinds get a `ReplaceableKey` and a `DatedID` entry in `ReplaceableEvents`; the **latest** revision (by date, then id) is what smart queries return.
- **Kind 5 = deletion event.** `scribeNewEvent` requires every `EventRefTag` in a kind-5 event to reference an existing event owned by the same author, else `SignedNoteError.invalidKind5PublicKey` / `.invalidKind5Tag`. Queries subtract deleted ids (and the kind-5 events themselves).
- `ReplaceableKey(pubkey:kind:dTag:)` — optional pubkey/dTag encoded with existence flags; its `MDB_compare_f` is a raw byte compare. Used as the index key for replaceable events.

### Write path invariants
- Every event written through `scribeNewEvent` is checked for write access and stored with its signature (the server verifies `event.isValidSignature()` before scribing). Ephemeral events are rejected.
- Writes are transactional: event is inserted with `.noOverwrite` (duplicate id → `LMDBError.keyExists`), then all indexes are updated in the same transaction, then committed.

## Conventions

- **Swift Testing, never XCTest.**
- RAW (`rawdog`) serialization: custom types conform to `RAW_convertible` / `RAW_accessible` / `RAW_staticbuff` and implement `RAW_encode(count:)`, `RAW_encode(dest:)`, `init?(RAW_decode:count:)` manually. Match this style for new DB types.
- LMDB key types conform to `MDB_comparable` (see `Extensions/MdbComparable.swift` and the `MDB_compare_f` implementations in `ReplaceableKey`/`DatedID`).
- Swift 6 strict concurrency: types are `Sendable`, the shared subscription store is an **actor** (`NostrRequestsStore`), and the daemon runs under `ServiceGroup`. Long-running work uses `cancelWhenGracefulShutdown` + `withThrowingTaskGroup`.
- Logging uses swift-log; pass `logLevel: Logger.Level` explicitly. Color helpers in `LoggerColour.swift` (`red`/`green`/`yellow`/`orange`).
- `ByteBuffer` is the event content type; `ByteBuffer(rawObject:)` serializes any `RAW_encodable`.
- Dependencies: two are **local path packages** (`../nostr-kit-swift`, `../openpgp-kit-swift`) — builds require those sibling checkouts. Others pinned: `rawdog` 21.x, `QuickLMDB` 14.x, `swift-nio` 2.81.x, `bedrock` 7.1.x, `swift-service-lifecycle` 2.6.x, `swift-argument-parser` 1.5.x, `wireguard-swift` (revision pinned).

## Daemon behavior (for work on the server)

`TesseraService.run()`:
1. Opens `TesseraDB`, loads WireGuard peer config (`peer-config.json`).
2. Creates a `WGInterface<KCPChannels>` (mtu 1400) bound to `myPort`, starts it, waits for channel init.
3. Spawns one task per peer; each consumes that peer's inbound FIFO and decodes raw bytes as NOSTR messages (`EVENT` / `REQ` / `CLOSE`), falling through decode attempts in that order.
4. `REQ` → register subscription in `NostrRequestsStore`, query (`smart` or `dumb` depending on `fetchHistory`), send matching events + `EOSE`. `EVENT` → verify signature, `scribeNewEvent` (send a `NOTICE` on `invalidWriteAccess`), fan out to matching live subscriptions, echo deletion events. `CLOSE` → drop the subscription.

The service is meant to run **indefinitely** and should only go down on critical errors or for updates.
