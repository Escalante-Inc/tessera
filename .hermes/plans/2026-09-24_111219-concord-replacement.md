# Concord Replacement Implementation Plan
# (tessera: negentropy-swift → QuickLMDB `concord`)

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Replace the `negentropy-swift` dependency in tessera with the `concord` library product baked into QuickLMDB's `v22-rewrite` branch, preserving current sync semantics (convergence, verification, reindexing) and the full e2e sync test coverage.

**Architecture:** `concord` = pure synchronous reconciliation engine + QuickLMDB index adapter (transport-agnostic, values travel as bytes). Tessera supplies the missing layers: (1) a minimal wire codec over the existing `NEGT`-magic datagram stream, (2) a `ConcordTransport` bridging the WG channel + per-peer `syncFIFO`, (3) a round driver running `ConcordSession.runRound()` on a dedicated thread under one write transaction, (4) a simplified sync manager (the db-signature handshake disappears). Unchanged: `isNegentropyFrame` routing, pubkey tie-break role selection, `SyncGate` writer serialization, `reindexAfterSync` verification, DB layout, access checks.

**Tech Stack:** Swift 6.2+ (QuickLMDB `v22-rewrite` needs tools 6.3), QuickLMDB `v22-rewrite` @ `0eff38d`, rawdog 22.x, swift-nio + wireguard-userspace-nio (KCP), bedrock_fifo, bedrock_pthread (or Foundation Thread), Swift Testing.

---

## Verified current-state facts (2026-09-24)

- QuickLMDB `origin/v22-rewrite` = `0eff38d84cd81c3a0303670b5c085a7ab9767b09`; ships `Sources/concord/` (9 files) + `Tests/ConcordTests/` (6 files) + `.library(name: "concord")`. The local clone's ref was stale (`7133421`) — fetch via HTTPS: `git fetch https://github.com/tannerdsilva/QuickLMDB.git v22-rewrite:refs/remotes/origin/v22-rewrite`.
- tessera `Package.swift` pins QuickLMDB to `branch: "rawdog-v22-bump"` (URL) and negentropy-swift to `bwyma1/negentropy-swift` branch `main` (URL, with a commented `../negentropy-swift` path).
- negentropy-swift ALSO pins QuickLMDB `branch: "rawdog-v22-bump"` and uses the old transaction dialect (`Transaction(env:readOnly:)`) in `SyncThread.swift:275`, `ListenThread.swift:219`, and ~7 test sites.
- QuickLMDB `v22-rewrite` dialect is **typed**: `Transaction<Write>(env:)`, `Transaction<Read>(env:)` (`~Copyable`), `Database(env:name:flags:tx: borrowing Transaction<Write>)`. Old `Transaction(env:readOnly:)` does not exist there.
- `concord` API (all confirmed from source):
  - `ConcordKey` = `RAW_staticbuff & MDB_comparable & Comparable & Hashable & Sendable`
  - `ConcordIndex<Key, Value>`: `entryCount`, `firstKey`, `keyCount(in:_:)`, `fingerprint(of:_:)`, `fingerprintAndAdvance(begin:count:end:)`, `forEachKey(in:_:_:)`, `loadBytes(_:) -> (any ConcordByteView)?`, `storeBytes(_:_:)`; `Value: MDB_convertible`
  - `ConcordLMDBIndex<Key, Value>(database: Database, cursor: Cursor)` — raw `MDB_val` walks, zero-copy; **`storeBytes` uses `MDB_cursor_set_entry(flags: 0)` (overwrite)**
  - `ConcordSession<Index, Transport>(index:transport:role:buckets:oneWaySync:).runRound()` — synchronous, one long-lived write txn per round
  - `ConcordTransport<Key, Value>: Sendable` { `send`, `receive() -> ConcordMessage?`, `close` }; messages are NOT `Sendable` (borrowed byte views)
  - `ConcordMessage`: `.reconcile(ConcordReconcile)`, `.dataQuery(Key)`, `.data(key:bytes:)`, `.finish`; `ConcordSection`: `.skip(Key?)`, `.fingerprint(Key?, Fingerprint)`, `.idList(Key?, [Key])`
  - `Fingerprint` = `@RAW_staticbuff(bytes: 24)` (blake2s over raw key bytes)
  - `ConcordError`: emptyReconcile, nonIncreasingBounds, missingKey, unexpectedFinish, prematureClose, unexpectedDataQuery
- tessera fits with zero type work on schema: `NOSTR_id` is already `RAW_staticbuff + MDB_comparable(@retroactive) + Comparable + Hashable + Sendable + NOSTR_tag_value`; `TesseraSignedEvent = NOSTR_event_signed<UnsignedEvent<ByteBuffer>>` already satisfies `MDB_convertible` (it is a `Database.Strict<NOSTR_id, TesseraSignedEvent>` value today).
- tessera syncs exactly ONE strict DB today (`syncStrictDBs == [signedEvents]`, `basicDBs == []`).
- Service routing: `Service.swift:202` (`isNegentropyFrame`) yields NEGT-magic datagrams into per-peer `syncFIFO`; `NegentropySyncManager` consumes them; `Service.swift:163-174` spawns `runForever(gate:)`.
- E2E harness (`Tests/tessera-tests/NegentropySyncE2ETests.swift:139/148`) currently calls `NegentropySyncThread.run`/`NegentropyListenThread.run` directly over loopback WG + FIFOs.
- bedrock_fifo offers `makeSyncConsumerBlocking()` / `makeSyncConsumerBlockingExplicit()` (blocking `.next()`), and `makeSyncConsumerNonBlocking()` (used by the manager's `drainStaleFrames`/`awaitFirstFrame`).

---

## Decisions (confirm before execution; recommendations first)

| # | Decision | Recommendation |
|---|----------|----------------|
| D1 | **Wire format**: (a) fresh minimal format (recommended) vs (b) byte-compatible reimplementation of negentropy-swift's frames | (a) Fresh format v1 (spec below). All peers upgrade together; (b) only if a mixed-version fleet must keep syncing during rollout. |
| D2 | **Overwrite hardening**: concord's `storeBytes` overwrites existing keys | Do NOT modify concord at first. Keep `reindexAfterSync` sweep as the tamper defense (same as today). Optional follow-up: a `ConcordIndex` delegating wrapper or concord patch adding `noOverwrite`/verify-before-write (upstream decision). |
| D3 | **Dependency sequencing**: QuickLMDB branch switch breaks BOTH tessera and negentropy-swift (old Tx dialect) | Stage it: Phase 0 migrates BOTH packages' QuickLMDB usage to `v22-rewrite` (negentropy-swift stays installed until Phase 5 → tree builds at every step). Alternative accepted: cut over atomically and lose sync until Phase 4 lands. |
| D4 | **Transaction dialect**: adopt `v22-rewrite` typed `Transaction<Write>`/`<Read>` everywhere in tessera-core | Mandatory (D3). Directory-wide mechanical change; ~15-20 call sites. |
| D5 | **Sync suite build config**: existing sync e2e needs `-c release` (QuickLMDB DEBUG cursor assert) | Verify whether `v22-rewrite` still has the assert (concord's index walks use fresh `opSetRange` seeks — likely OK). Keep `-c release` policy for sync tests until proven. |
| D6 | **Value decode semantics**: concord stores bytes verbatim (never decodes) | Accepted: well-framed-but-invalid values are stored then swept by reindex pass 1 (identical end state to today; today's decode-abort is stronger per-message but the sweep covers it). |

---

## Wire format v1 (proposed, pending D1)

One message per WG datagram (same as today — sync frames are single datagrams after the NEGT magic).

```
frame := "NEGT" (4) | version (1 = 0x01) | msgType (1) | payload
msgType: 0x01 reconcile | 0x02 dataQuery | 0x03 data | 0x04 finish

reconcile payload := sectionCount (UInt32 BE) | section*
section := tag (1) | hasBound (1) [| bound (32 bytes, key bytes)] [| sectionData]
  tag 0x00 skip       -> sectionData: none
  tag 0x01 fingerprint-> sectionData: 24 bytes (fingerprint)
  tag 0x02 idList     -> sectionData: keyCount (UInt32 BE) | keyCount * 32 bytes
dataQuery payload := key (32 bytes)
data payload      := key (32 bytes) | valueLen (UInt32 BE) | value bytes (verbatim)
finish payload    := none
```

- Bounds are **full keys** (no common-prefix compression — simpler; the old wire's bound compression is a transport concern concord explicitly leaves out).
- `version` byte gives a clean failure mode both ways (unknown → `ConcordError`-style `badVersion` throw → round aborts; no silent misparse).
- All integers big-endian; keys are `NOSTR_id` raw bytes (32).
- Value bytes are copied into the frame buffer at send time (the one transport-boundary copy concord sanctions).

---

## Step-by-step plan

### Phase 0 — QuickLMDB `v22-rewrite` migration (both consumers), no behavior change

**Task 0.1 — Refresh the local QuickLMDB checkout ref (read-only)**
```bash
cd /Users/brockwyma/Documents/SwiftProjects/QuickLMDB
git fetch https://github.com/tannerdsilva/QuickLMDB.git v22-rewrite:refs/remotes/origin/v22-rewrite
git rev-parse origin/v22-rewrite   # expect 0eff38d84cd81c3a0303670b5c085a7ab9767b09
```
Commit: `chore: refresh QuickLMDB v22-rewrite ref`

**Task 0.2 — Baseline green run**
```bash
cd /Users/brockwyma/Documents/SwiftProjects/tessera && swift build --build-tests --skip-update && swift test -c release --skip-update
```
Record the passing count (currently 57/7 suites + sync e2e) — this is the regression baseline.

**Task 0.3 — Switch tessera's QuickLMDB pin**
- Modify `tessera/Package.swift:33`: `branch: "rawdog-v22-bump"` → `branch: "v22-rewrite"`.
- `swift package resolve`; expect QuickLMDB `0eff38d` in `Package.resolved`.

**Task 0.4 — Migrate tessera-core to the typed transaction dialect**
Inventory (the exact set may grow during the build):
- `Sources/tessera-core/Database/WriteOperations/Write.swift` (scribeNewEvent/scribeNewUser `Transaction(env:readOnly:)`)
- `Sources/tessera-core/Database/ReadOperations/Query.swift`, `CheckUserAccess.swift`
- `Sources/tessera-core/Database/WriteOperations/SyncReindex.swift`
- `Sources/tessera-core/Database/TesseraDB.swift` (init, DB creation flags/compare setup — catalog exact `Database` creation args so the concord driver can mirror them)
- `Sources/tessera-core/Database/Structs/Indexing/*`, `Extensions/*` (any `Database.Strict`/cursor API diffs)
- `Tests/tessera-tests/*` (all `Transaction(env:...)` sites)

Mechanical shape (`QuickLMDB` v22-rewrite):
```swift
let newTrans = try Transaction<Write>(env: env)           // was: Transaction(env: env, readOnly: false)
let readTrans = try Transaction<Read>(env: env)           // was: Transaction(env: env, readOnly: true)
```
Note `~Copyable`: `guard let`/`defer` patterns that consumed `newTrans` twice must switch to `borrowing` params or restructure (existing code already passes `tx: borrowing Transaction` in most helpers — recheck against the new type name).

Verification: `swift build --build-tests --skip-update` → 0 errors. Then `swift test -c release --skip-update` — **the NON-sync suites must pass** (sync e2e may still run if negentropy-swift still builds; do not treat sync e2e failures here as regressions if they are dialect noise).
Commit: `chore(tessera): adopt QuickLMDB v22-rewrite typed Transaction dialect`

**Task 0.5 — Migrate negentropy-swift to the same pin + dialect (keep it installed until Phase 5)**
- `negentropy-swift/Package.swift:16`: `branch: "rawdog-v22-bump"` → `branch: "v22-rewrite"`.
- Fix `Sources/negentropy-swift/PThreads/SyncThread.swift:275`, `ListenThread.swift:219`, and all `Tests/negentropy-swiftTests/negentropy_swiftTests.swift` transaction sites.
- Any QuickLMDB cursor API churn that surfaces (its `splitRange`/`countEntries` use `DatabaseIndexVector` extensions — only cursor methods, likely unchanged).
- Verify: `cd /Users/brockwyma/Documents/SwiftProjects/negentropy-swift && swift build --build-tests --skip-update && swift test -c release --skip-update` (baseline 8/8).
Commit: `chore(negentropy-swift): adopt QuickLMDB v22-rewrite pin and Transaction dialect`

### Phase 1 — Concord conformance + unit tests (no tessera wiring yet)

**Task 1.1 — Verify concord builds standalone**
```bash
cd /Users/brockwyma/Documents/SwiftProjects/QuickLMDB
git checkout v22-rewrite   # or worktree: git worktree add ../QuickLMDB-concord v22-rewrite
swift build --build-tests && swift test --filter ConcordTests
```
Expected: ConcordTests pass (rounds, LMDB, cross-impl). This also answers D5 (DEBUG assert behavior on `v22-rewrite`).
Commit (in QuickLMDB repo if worktree): n/a — upstream branch, do not commit.

**Task 1.2 — Conform `NOSTR_id` to `ConcordKey`**
- Create `Sources/tessera-core/Extensions/NostrIdConcordKey.swift`:
```swift
import RAW
import QuickLMDB
import nostr_kit_swift
import concord

extension NOSTR_id: @retroactive ConcordKey {}
```
- Keep or fold `NostrIdDatabaseIndexVector.swift` (deleted in Phase 5; until then both conformances coexist).
Verify: `swift build --build-tests --skip-update` (tessera-core now depends on `concord` product — add `.product(name: "concord", package: "QuickLMDB")` to the tessera-core target deps in `Package.swift`).
Commit: `feat(tessera-core): NOSTR_id conforms to concord ConcordKey`

**Task 1.3 — Codec with TDD (pure, no networking)**
- Create `Sources/tessera/Concord/ConcordWireCodec.swift` (or `Sources/tessera-core/Concord/` if export needed — recommend `tessera` executable target, since sync glue lives there; if `NegentropySyncManager` stays in `tessera`, codec goes there too).
- API:
```swift
enum ConcordWireCodecError: Swift.Error { case badVersion, badType, truncated, nonMonotonic, badStringCount }
struct ConcordWireCodec {
    static func encode<Key: ConcordKey, Value: MDB_convertible>(_ m: ConcordMessage<Key, Value>) throws -> ByteBuffer
    static func decode<Key: ConcordKey, Value: MDB_convertible>(_ frame: ByteBuffer) throws -> ConcordMessage<Key, Value>
}
```
- Write failing tests first in `Tests/tessera-tests/ConcordWireCodecTests.swift`:
  - round-trip for every message/section shape (skip/fingerprint/idList with nil + non-nil bounds; empty idList; empty reconcile sections → reject (emptyReconcile is engine-side, codec may allow and let engine throw))
  - truncation at EVERY byte boundary for a representative frame → throws `truncated`, never traps
  - bad version / bad type byte → throws
  - value bytes survive round-trip byte-for-byte (compare `[UInt8]`)
- Implementation notes: read/write via `ByteBuffer` (readInteger/writeInteger big-endian; `readBytes`). Key bytes: `key.RAW_access_immutable(UnsafeBufferPointer<UInt8>.self) { Array($0) }`; decode via `Key(RAW_decode: buffer)!` (exact 32 bytes — guard count == 32 first). Value: `ConcordOwnedBytes` at decode (detach — this crosses only the round's thread here anyway).
Verify: `swift test -c release --filter ConcordWireCodecTests` → all pass.
Commit: `feat(tessera): concord wire codec v1 with truncation tests`

**Task 1.4 — Forge-tolerance test (security-adjacent, optional but recommended)**
- Test that a **malformed-but-well-framed** frame (e.g., reconcile with non-increasing bounds, fingerprint section with no bound after skip, idList count that overruns the datagram) maps to a throw from decode → driver aborts + rollback (assert in Phase 3 integration). Also test `version: 0x02` rejection.
Commit: `test(tessera): codec rejects malformed/unknown-version frames`

### Phase 2 — WG transport + round driver

**Task 2.1 — `ConcordTransport` over WG channel + FIFO**
- Create `Sources/tessera/Concord/ConcordWGTransport.swift`:
```swift
struct ConcordWGTransport<Key: ConcordKey, Value: MDB_convertible>: ConcordTransport {
    let channel: Channel
    let peerPublicKey: PublicKey
    let syncFIFO: FIFO<ByteBuffer, Swift.Error>

    func send(_ message: ConcordMessage<Key, Value>) throws {
        let frame = try ConcordWireCodec.encode(message)
        try WGInterface<KCPChannels>.write(channel: channel, publicKey: peerPublicKey, data: frame)
    }
    func receive() throws -> ConcordMessage<Key, Value>? {
        // blocking consumer (dedicated round thread): makeSyncConsumerBlocking()
        // nil consumer result => orderly close => return nil (engine throws prematureClose if unexpected)
        guard let frame = try? syncFIFO.makeSyncConsumerBlocking().next() else { return nil }
        return try ConcordWireCodec.decode(frame)
    }
    func close() throws {}
}
```
- Confirm exact `SyncConsumerBlocking.next()` semantics during implementation (blocking `ConsumeResult` vs `Element?`) from `bedrock_fifo/FIFO.swift:161-185`.
- Sendable check: `Channel`, `FIFO`, `PublicKey` are all `Sendable` — the struct satisfies the protocol constraint; verify with compiler.

**Task 2.2 — Round driver (thread + write-tx scoping)**
- Create `Sources/tessera/Concord/ConcordRoundDriver.swift`, mirroring `Tests/ConcordTests/LMDBRoundTests.swift`:
```swift
struct ConcordRoundOutcome { /* nothing needed yet; commit/abort is the contract */ }

func runConcordRound(
    env: Environment, databaseName: String,
    oneWay: Bool, role: ConcordRole,
    transport: any ConcordTransport<...>  // generic erasure not needed — make this generic
) throws {
    let txn = try Transaction<Write>(env: env)
    do {
        // DB name/flags must match how TesseraDB created signedEvents (catalog in 0.4).
        let db = try Database(env: env, name: databaseName, flags: [], tx: txn)
        let cursor = try Cursor(db: db, tx: txn)
        let index = ConcordLMDBIndex<NOSTR_id, TesseraSignedEvent>(database: db, cursor: cursor)
        do {
            try ConcordSession(index: index, transport: transport, role: role).runRound()
        } catch {
            txn.abort(); throw error
        }
        // index/cursor/db released here — before commit (cursor-after-tx-close = freed-memory trap)
        try txn.commit()
    }
}
```
- The driver runs on a dedicated `Thread` (Foundation) or bedrock PThread — same shape as the test: `Thread { defer { done.signal() }; do { ... } catch { errorBox.set($0) } }`, semaphores for completion, rethrow from the caller.
- **Important**: `runConcordRound` must be invoked from the round's own thread with `Transaction<Write>` opened ON that thread (LMDB tx is thread-confined) — the Thread closure opens the txn (test pattern). The async caller only awaits completion.

**Task 2.3 — Wire the manager (delete the handshake)**
- Modify `Sources/tessera/Service/NegentropySyncManager.swift`:
  - Delete `awaitFirstFrame` (lines ~74-83) and the `firstFrame` plumbing; responder no longer needs the initiator's pre-amble — concord's responder just starts `receive()`-ing.
  - Replace `NegentropySyncThread.run(...)` / `NegentropyListenThread.run(...)` (lines 95-109) with `runConcordRound(env: tesseraDB.env, databaseName: "signedEvents", role: isInitiator ? .initiator : .responder, transport: ConcordWGTransport(...), oneWay: false)` on a Thread, awaited via semaphore.
  - Keep: `isInitiator` (pubkey tie-break, lines 59-62), `drainStaleFrames`, `SyncGate` usage in `runForever`, `reindexAfterSync`.
- Expose `tesseraDB.env` if not already public (check `TesseraDB.h`/`TesseraDB.swift`; add `public var envForSync: Environment` accessor if needed).
Commit: `feat(tessera): concord-driven sync rounds over WG transport`

### Phase 3 — Integration tests (rework e2e harness)

**Task 3.1 — Replace e2e engine calls, keep the 11 scenarios**
- Modify `Tests/tessera-tests/NegentropySyncE2ETests.swift:139/148`: replace `NegentropySyncThread.run`/`NegentropyListenThread.run` with the same driver + transport used in production (real loopback WG interfaces + real FIFOs + real envs), keeping the deterministic-completion pattern (await both threads' completion signals; cancel WG interface tasks; no fixed sleeps).
- Keep all scenarios: `syncConvergesBothWays`, `syncedEventsAreQueryableAfterReindex`, `reindexDropsTamperedValues`, empty-responder/initiator, newest-replaceable, kind-5 propagation, idempotent double sync, large dataset, tag-heavy, scaling benchmark.
- Add one new test: `roundAbortsAndRollsBackOnMalformedFrame` — inject a hand-crafted garbage frame (bad version byte) into the responder's FIFO and assert the initiator/responder round fails and the store is unchanged (rollback proof, D2/D6 note).

**Task 3.2 — Full suite runs**
```bash
cd /Users/brockwyma/Documents/SwiftProjects/tessera
swift test -c release --skip-update        # full: expect all suites green including reworked sync e2e
swift test --skip-update                    # debug: record whether QuickLMDB DEBUG assert still bites (D5)
```
Commit: `test(tessera): rework negentropy e2e onto concord driver + rollback test`

### Phase 4 — Hardening + performance verification

**Task 4.1 — Overwrite policy (D2 decision point)**
- If D2 = defer (recommended): document in `ConcordRoundOutcome`/manager comments that `storeBytes` overwrite is mitigated only by reindex pass 1; add no code.
- If D2 = harden: implement a `ConcordVerifyBeforeStoreIndex` delegating wrapper (satisfies `ConcordIndex`, holds the LMDB index; `storeBytes` first `containsEntry`-checks, then delegates) — pure tessera-side, no concord edit; add unit test that a same-key-different-value frame leaves the original intact.
- Commit: `feat(tessera): [optional] verify-before-store concord index wrapper`

**Task 4.2 — Scaling sanity**
- Re-run `syncScalesSubExponentiallyWithDatabaseSize` with the concord path (expect the same ~linear exponent band; report fitted exponent vs the 1.03 baseline). Record in the plan's validation notes.
Commit: `chore(tessera): record concord scaling results`

### Phase 5 — Remove negentropy-swift

**Task 5.1 — Dep removal**
- `tessera/Package.swift`: remove `.package(url: "https://github.com/bwyma1/negentropy-swift", branch: "main")` (+ commented path) and the product use in `tessera-core` target deps; remove the tester's `import negentropy_swift` lines from `NegentropySyncManager.swift`, `SyncReindex.swift`, `NostrIdDatabaseIndexVector.swift`, `NegentropySyncE2ETests.swift`. Delete `Sources/tessera-core/Extensions/NostrIdDatabaseIndexVector.swift` (superseded by `NostrIdConcordKey.swift`).
- `negentropy-swift/Package.swift` may stay as-is (repo no longer consumed) — revert the Phase 0.5 changes there optionally, or leave; do NOT delete the sibling repo.
- `swift package resolve` + `swift build --build-tests --skip-update` → 0 errors, 0 warnings.
Commit: `chore(tessera): remove negentropy-swift dependency`

**Task 5.2 — Final full validation**
```bash
cd /Users/brockwyma/Documents/SwiftProjects/tessera
swift build 2>&1 | grep -cE "warning:|error:"          # expect 0/0
swift test -c release --skip-update                     # expect full green (57 + reworked sync e2e)
swift test --skip-update                                # document debug behavior (D5)
cd /Users/brockwyma/Documents/SwiftProjects/QuickLMDB && swift test --filter ConcordTests   # upstream still green
```

### Phase 6 — Docs / skill update

**Task 6.1 — Update `tessera-server-development` skill notes**: negentropy-server-sync reference — replace "negentropy-swift integration" section with the concord architecture (transport owned by tessera, wire format v1, handshake removed, single-DB only, storeBytes-overwrite note, debug-assert status on v22-rewrite).
Commit: `docs: concord sync integration notes`

---

## Files likely to change (summary)

**tessera:**
- `Package.swift` (QuickLMDB branch, concord product, drop negentropy-swift)
- `Sources/tessera-core/...` (typed `Transaction<M>` migration; DB-creation catalog)
- `Sources/tessera/Concord/ConcordWireCodec.swift` (new)
- `Sources/tessera/Concord/ConcordWGTransport.swift` (new)
- `Sources/tessera/Concord/ConcordRoundDriver.swift` (new)
- `Sources/tessera/Service/NegentropySyncManager.swift` (rewrite of round invocation)
- `Sources/tessera/Service/Service.swift` (likely unchanged; verify)
- `Sources/tessera-core/Extensions/NostrIdConcordKey.swift` (new)
- `Sources/tessera-core/Extensions/NostrIdDatabaseIndexVector.swift` (deleted in Phase 5)
- `Tests/tessera-tests/ConcordWireCodecTests.swift` (new)
- `Tests/tessera-tests/NegentropySyncE2ETests.swift` (rework)
- `Tests/tessera-tests/tests.swift` (dialect test-site migration)

**negentropy-swift (temporary, Phase 0 only):** `Package.swift`, `PThreads/SyncThread.swift`, `PThreads/ListenThread.swift`, `Tests/negentropy-swiftTests/negentropy_swiftTests.swift`

**QuickLMDB:** none (v22-rewrite upstream; local checkout only for verification)

## Validation matrix

| Gate | Command | Pass condition |
|---|---|---|
| Build (no warnings) | `swift build --build-tests --skip-update` | 0 errors, 0 warnings |
| Unit (codec) | `swift test -c release --filter ConcordWireCodecTests` | all pass incl. truncation fuzz |
| Full sync e2e (release) | `swift test -c release --skip-update` | all sync scenarios green |
| Convergence (live) | `mdb_stat`/`mdb_dump` per `tessera-server-development` → `lmdb-convergence-verification.md` | hashes match after round |
| Scaling | `syncScalesSubExponentiallyWithDatabaseSize` | exponent ≈ 1.0 (linear) |
| Tamper | `reindexDropsTamperedValues` + new rollback test | drops/sweeps unchanged |

## Risks & mitigations

1. **QuickLMDB typed-Tx churn is the biggest unknown** (Task 0.4/0.5) — do it first, isolate in its own commits, keep negentropy-swift building while it's still a dep. Mitigate by reading `Transaction.swift` + diffing call sites before editing (the `~Copyable` `borrowing` rules are the trap).
2. **Wire format lock-in** — version byte prevents silent misparse; both peers must be new build (D1). If a fleet must be mixed, switch to decision (b).
3. **`storeBytes` overwrite + no decode** — covered by D2/D6 analysis; reindex sweep is the boundary; optional verify-before-store wrapper staged as Phase 4.1.
4. **Cursor-after-transaction-close trap** — the index/cursor must deallocate before `txn.commit()`; the driver follows the concord test's exact scoping (verified pattern). Add the rollback test (3.1) to lock it in.
5. **Wireguard datagram budget** — one message per datagram; events are small; same constraint as today. If future large values are needed, chunking is a transport concern (out of scope).
6. **Debug-mode QuickLMDB assert** — recheck on v22-rewrite (Task 1.1); keep `-c release` for the sync suite either way; document in skill.
7. **`SyncGate` + single-writer round**: unchanged semantics; concord doc suggests off-peak/spaced scheduling — keep current cadence.

## Open questions for the user

1. D1: fresh wire format (recommended) — confirm.
2. D3: staged migration keeping negentropy-swift until Phase 5 (recommended) vs atomic cut-over.
3. D2: defer overwrite hardening (recommended) or build the verify-before-store wrapper in Phase 4.
4. Where the sync glue should live: keep in the `tessera` executable target (`NegentropySyncManager` sits there today) — confirm no wish to move into `tessera-core` for client reuse.
