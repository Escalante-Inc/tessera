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
- `CLI/Run.swift` — `@main struct CLI: AsyncParsableCommand`, command name `tessera-service`. Subcommands: `Run`, `GenerateKeys`, `GenerateEd25519Keys`, `CreateNewAccessLevel`, `CreateUser`, `CreateUnboundedAdmin`, `CreateUnboundedYubikeyAdmin`, `Config`, `Admin`, `WebUI`.
  - **`Run`** starts the daemon: builds `TesseraService` and runs it in a `ServiceGroup` from `swift-service-lifecycle`.
  - **`Admin`** (`CLI/Admin.swift`) — read-only admin inspection of a relay database: `admin users` (with active/inactive status from event timestamps), `admin stats`, `admin peers`, `admin transactions`, `admin access-levels`. Safe to run while the daemon is live (readers never block the writer). If a database is missing at the path it errors instead of creating one.
  - **`WebUI`** (`CLI/WebUICommand.swift`, macOS-only, uses the GitHub `no-webui` dependency) — hosts an admin dashboard (same data as `admin`) over HTTP + WebSocket via no-webui's `WebUIServer` (`Service/AdminWebUIServer.swift`). Default bind `127.0.0.1:9777`. A poller (`--poll-interval`, default 15s, 0 disables) re-renders the visible section and `broadcast`s it to every connected browser, so the page stays live with no manual refresh; pushes render outside a RenderContext (attributes re-emitted, nothing re-registered) and skip when the section changed mid-render **or during a critical moment** (an add form is open, a removal confirm is staged, or the one-time secret/created-user panel is visible) — a fragment swap would wipe in-progress input or destroy a text selection mid-copy, so `broadcastLoop` re-checks `isCriticalMoment()` before and after rendering and drops the push; the secret panel persists server-side (`createdUser`/`createdByoUser` are NOT cleared by the submit handler, only by navigation) so it survives across pushes until the admin moves on. The add-user form takes an **optional public key** (base64, the event-author key shown in the Users table): when supplied, the user is created under that existing key with no secret generated (the user signs with the private half on their own machine); when empty, a fresh keypair is generated and its secret shown once. Duplicate keys are rejected with a friendly message. Public Key cells in the Users **and Peers** tables carry a copy icon (`/ui/admin-copy.js` + `data-copy-key` attributes; clipboard write is client-side, and the `.copied` class flashes on success).
  - **Admin editing**: with `--admin-key <base64 RAW_dh25519.PrivateKey>` the dashboard can **add users**, **add access levels**, and **remove users**. Add-user **generates a fresh keypair per user** (a user *is* a key pair — signing with the admin key would collide on `userIndex`), scribes a kind-0 event, and surfaces the new base64 secret once in a one-time panel (cleared on navigation — it cannot be recovered). Access-level names resolve against the DB's kind-1 events. **Add access level** signs a kind-1 event (`perm` + `permName` tags) with the admin key via `scribeNewEvent`; duplicate level numbers or names are rejected. If the admin key has no user record in the DB, the first mutation bootstraps a full-access "Admin" user (same trust boundary as `create-unbounded-admin`) — otherwise `scribeNewEvent` fails with `userDoesNotExist`. **Remove users** uses `TesseraDB.adminDeleteUser` in `tessera-core/Admin/Mutations.swift` (an administrative deletion that clears `userIndex` + the profile event and all its index entries; a protocol kind-5 would never clear `userIndex`). **Peers** can be added/removed via `editConfig` on `peer-config.json`; the daemon only reads the file at startup, so the Peers section notes that changes apply on restart. Removals always stage an inline confirm panel (Remove/Cancel) before acting. Without `--admin-key` the dashboard is fully read-only.
  - `CreateUser` / `CreateUnboundedAdmin` / `CreateUnboundedYubikeyAdmin` / `CreateNewAccessLevel` require a plugged-in **YubiKey** (OpenPGP smartcard) or a secret key, and write a signed event into the DB.
- `CLI/WireguardConfiguration.swift` — the `Config` subcommand + JSON peer-config file handling (`WireguardConfig`, `PeerInfo`, `loadConfig`/`writeConfig`/`editConfig`). Config file is `peer-config.json` in the config dir. Endpoints are encoded as `"addr:port"` strings and keep-alives as fractional seconds (see the `Endpoint`/`TimeAmount` Codable extensions in wireguard-swift).
- `CLI/Arguments.swift` — `ExpressibleByArgument` extensions for `PublicKey` / `MemoryGuarded<PrivateKey>` (base64 decode) and `Path`.
- `Service/Service.swift` — **`TesseraService: Service`** — the daemon. Runs one WireGuard interface (`WGInterface<KCPChannels>`, mtu 1400) on `myPort`; one task per configured peer that decodes incoming data as NOSTR `EVENT`/`REQ`/`CLOSE` messages, scribes events, answers `REQ` with matching events + `EOSE`, tracks active subscriptions in the `NostrRequestsStore` actor, and fans out new events to matching live subscriptions. The daemon also appends peer transactions (events in/out, REQs served, sync rounds, rejections) to `peer-transactions.jsonl` next to the database.
- `Service/AdminWebUIServer.swift` — the no-webui dashboard server + views used by the `webui` subcommand (whole file `#if canImport(WebUI)`-guarded so Linux builds skip it). Built on no-webui 2.x: a `WebUIServer(router:eventRouter:config:)` hosts the page + WS at `/ws`; the page is a per-request `BufferRendering` document rendered inside the server-owned `RenderContext` (so delegated controls self-register into the connection's render session); the engine script + `webui-config` meta (with the render token) are emitted automatically by `WebUIDocument`. Fragment updates from handlers re-emit stable `data-component-id` attributes without re-registering.
- `Service/NegentropySyncManager.swift` — per-peer concord sync loop; records round results into the peer transaction log.
- `SmartCard.entitlements` — `com.apple.security.smartcard = true`; applied by `build.sh`.

### Sources/tessera-core/Admin
- `AdminQueries.swift` — read-only admin queries over the existing tables (no schema change): `adminListUsers` (profiles + per-author event counts + last-activity dates from the author index), `adminEventStats` (per-kind/per-application/per-author counts, date range, 24h/7d windows, replaceable/deletion counts — index-only, never scans the primary store), `adminListAccessLevels` (kind-1 events). All `@MDB_transact(.readOnly)`. Result structs (`AdminUserInfo`, `AdminEventStats`, `AdminAccessLevelInfo`) are `Codable` so both the CLI and the webui consume them.
- `PeerTransactionLog.swift` — `PeerTransactionLog`: a `Mutex`-guarded JSONL appender (`<databasePath>/peer-transactions.jsonl`) with size-based rotation (keeps the newest ~2000 records), plus `PeerTransactionRecord`. `read(limit:)` returns the newest records **first** (used by both admin interfaces). Used by the daemon to record peer traffic and by both admin interfaces to display it.

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

Admin inspection (read-only, safe against a live relay):

```bash
tessera-service admin users --database-path ~/tessera_lmdb --window 7
tessera-service admin stats --database-path ~/tessera_lmdb
tessera-service admin peers --configuration-path ~
tessera-service admin transactions --database-path ~/tessera_lmdb --limit 20
tessera-service admin access-levels --database-path ~/tessera_lmdb
```

Admin webui (macOS only; uses the GitHub `no-webui` dependency):

```bash
tessera-service webui --database-path ~/tessera_lmdb --configuration-path ~ --port 9777
# then open http://127.0.0.1:9777
```

- **Authentication**: without `--admin-key <base64 RAW_dh25519.PrivateKey>` the dashboard is read-only and public. With it, every page load requires signing in — a login page takes a username and the admin secret key; the server derives the key's public half, constant-time-compares it against the configured admin key, and issues an HttpOnly session cookie (12 h). The username is display-only; the secret key is the only credential. A logout link sits in the header. `WebUIServerConfig.requireRenderToken` is enabled when auth is on, so WebSocket frames the login page never minted are refused. Cookies are parsed from the raw `Cookie` header (`AdminWebUIServer.cookies(from:)`) because no-webui 2.1.0 leaves `HTTPRequest.cookies` unpopulated.

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
- **Dependencies:** two are **local path packages** (`../nostr-kit-swift`, `../openpgp-kit-swift`) — builds require those sibling checkouts. `no-webui` comes from GitHub (`https://github.com/tannerdsilva/no-webui`, `2.0.0..<3.0.0`); its products (`WebUI`, `WebUIDesignSystem`, `WebUIServer`) are `.when(platforms: [.macOS])`-conditioned so Linux builds skip them. Others pinned: `rawdog` 21.x, `QuickLMDB` 14.x, `swift-nio` 2.81.x, `bedrock` 7.1.x, `swift-service-lifecycle` 2.6.x, `swift-argument-parser` 1.5.x, `wireguard-swift` (revision pinned).

## Daemon behavior (for work on the server)

`TesseraService.run()`:
1. Opens `TesseraDB`, loads WireGuard peer config (`peer-config.json`).
2. Creates a `WGInterface<KCPChannels>` (mtu 1400) bound to `myPort`, starts it, waits for channel init.
3. Spawns one task per peer; each consumes that peer's inbound FIFO and decodes raw bytes as NOSTR messages (`EVENT` / `REQ` / `CLOSE`), falling through decode attempts in that order.
4. `REQ` → register subscription in `NostrRequestsStore`, query (`smart` or `dumb` depending on `fetchHistory`), send matching events + `EOSE`. `EVENT` → verify signature, `scribeNewEvent` (send a `NOTICE` on `invalidWriteAccess`), fan out to matching live subscriptions, echo deletion events. `CLOSE` → drop the subscription.

The service is meant to run **indefinitely** and should only go down on critical errors or for updates.
