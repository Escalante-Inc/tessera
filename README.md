# tessera

Tessera is a Swift server for NOSTR event applications. It ships as a single executable that is **both a long-running daemon and a CLI tool**. The daemon acts as a central connection point: it listens on a WireGuard interface (using [wireguard-swift](https://github.com/tannerdsilva/wireguard-swift)), accepts signed NOSTR events and subscription requests from **other tessera nodes and end-user applications**, stores everything in a local LMDB database, and fans events out to matching subscriptions.

Clients and servers talk to each other with **signed NOSTR events** serialized with the [RAW](https://github.com/tannerdsilva/rawdog) byte library, wrapped in NOSTR `REQ` / `EVENT` / `CLOSE` messages over the WireGuard channel. The `tessera-core` Swift package also provides the client-side building blocks (connection helpers, caching models, and a receiver protocol) to build clients built on the same protocol.

---

## Installation

```bash
git clone https://github.com/bwyma1/tessera.git

cd tessera
swift build
```

If you plan to use the **YubiKey/smartcard commands**, build with the provided script so the binary is re-signed with the SmartCard entitlement (`com.apple.security.smartcard`):

```bash
./build.sh
# binary lands at .build/debug/tessera (command name: tessera-service)
```

---

## Running a Tessera server

[Generate a WireGuard Key Pair](#generate-a-wireguard-key-pair)

[Configure Peers that May Connect](#configure-the-peers-that-may-connect)

[Start the Daemon](#start-the-daemon)

All interaction with the server is through the `tessera-service` executable, built at `.build/debug/tessera`.

### Generate a WireGuard key pair

Every tessera node (server *and* client) has its own WireGuard key pair. Generate one for the server:

```bash
.build/debug/tessera generate-keys
# Public Key:  <base64 public key>
# Private Key: <base64 private key>
```

Save both values — the **private key** is the server's identity (keep it secret), and the **public key** is what clients/peers will use to address it.

### Configure the peers that may connect

The server only accepts WireGuard connections from peers listed in its configuration file (`peer-config.json`, defaulting to your home directory). Add a peer by its public key:

```bash
.build/debug/tessera config add \
  --ip-address 10.0.0.2 \
  --port 51820 \
  --keep-alive 25 \
  <peers-public-key>
```

Manage the peer list with the `config` subcommands:

```bash
.build/debug/tessera config list                     # show configured peers
.build/debug/tessera config remove <public-key>      # remove a peer
.build/debug/tessera config clear                    # empty the configuration
.build/debug/tessera config delete                   # delete the config file entirely
```

### Start the daemon

```bash
.build/debug/tessera run \
  --database-path ~/tessera_lmdb \
  --configuration-path ~/ \
  <my-port> \
  <my-private-key>
```

- `<my-port>` — the UDP port the WireGuard interface binds to (this is the port clients/peers connect to).
- `<my-private-key>` — the server's WireGuard private key from step 1 (base64).
- `--database-path` — where the LMDB database (`tessera.mdb`) is stored. Defaults to `~/tessera_lmdb`.
- `--configuration-path` — where `peer-config.json` lives. Defaults to your home directory.

The daemon keeps running indefinitely: it initializes the WireGuard interface, listens for incoming encrypted traffic from configured peers, decodes NOSTR messages, scribes events to the database, answers subscription requests, and pushes live events to subscribers. Use `--help` on any subcommand for the full option list.

---

## Building a Tessera client

[Prerequisites / Dependencies](#prerequisites--dependencies)

[The Connection Wrapper](#the-connection-wrapper)

[The Receiver](#the-receiver)

[A Data Model](#a-data-model)

[Subscribing (REQ)](#subscribing-req)

[Sending Events](#sending-events)

[Deleting Events](#deleting-events)

[Message Reference](#message-reference)

[Key Concepts](#key-concepts)

This is a generic guide to connecting a client application to a Tessera server. Anything that talks to a Tessera needs the same pieces, regardless of what the app does:

1. **A WireGuard connection** to the server, through which all messages flow.
2. **A message layer** — everything on the wire is a RAW-serialized NOSTR message (`REQ`, `EVENT`, `CLOSE`, ...). Build/parse these with `nostr-kit-swift`.
3. **A receiver** — decodes inbound `EVENT` messages and routes them to the in-memory models. Implement `TesseraClientReceiver` from `tessera-core` to handle this.
4. **One or more models** — conform to `TesseraCompliantModel` to cache the events of a particular content type, keep "latest" and "history" indexes, and drive the UI.

### Prerequisites / dependencies

Add tessera (for `tessera-core`) and its protocol/nio dependencies to the client's `Package.swift`:

```swift
.package(url: "https://github.com/Escalante-Inc/tessera", branch: "main"),
.package(url: "https://github.com/bwyma1/nostr-kit-swift", branch: "main"),
.package(url: "https://github.com/tannerdsilva/rawdog.git", "21.0.0"..<"22.0.0"),
.package(url: "https://github.com/tannerdsilva/wireguard-swift.git", revision: "<pinned>"),
.package(url: "https://github.com/apple/swift-nio.git", "2.81.0"..<"3.0.0"),
.package(url: "https://github.com/tannerdsilva/bedrock.git", "7.1.0"..<"8.0.0"),
// target dependencies
.product(name: "tessera-core", package: "tessera"),
.product(name: "nostr-kit-swift", package: "nostr-kit-swift"),
.product(name: "wireguard-userspace-nio", package: "wireguard-swift"),
.product(name: "RAW", package: "rawdog"),
.product(name: "RAW_dh25519", package: "rawdog"),
.product(name: "RAW_ed25519", package: "rawdog"),
.product(name: "RAW_base64", package: "rawdog"),
.product(name: "NIO", package: "swift-nio"),
.product(name: "bedrock_fifo", package: "bedrock"),
```

The client also needs its own **WireGuard key pair** (generated with `generate-keys`, or on the server with the CLI) and a **Nostr (Ed25519) signing key** — the key used to sign events. The signing key is what the server uses to identity-check the client on writes.

### The connection wrapper

Wrap the WireGuard interface in an object owned by the app. It should:

- take the **server's** address/port and the client's own WireGuard key pair,
- start the interface and wait for the channel to initialize,
- expose a `write(_:)` method that RAW-encodes any value into a `ByteBuffer` and sends it to the server,
- provide a FIFO of inbound data that is consumed on a background task.

```swift
import Combine
import wireguard_userspace_nio
import tessera_core
import nostr_kit_swift
import NIO
import RAW
import RAW_dh25519
import bedrock_fifo

/// Owns the WireGuard connection to a Tessera server.
final class TesseraClient: ObservableObject {

    @Published var myPublicKey: RAW_dh25519.PublicKey!                          // the client's WireGuard public key
    @Published var myPrivateKey: MemoryGuarded<RAW_dh25519.PrivateKey>!         // the client's WireGuard private key
    @Published private(set) var interface: WGInterface<KCPChannels>! = nil

    var serverIP: String        // e.g. "127.0.0.1" or the server's real address
    var serverPort: Int         // the server's `my-port`

    private var connectionTask: Task<Void, Never>?

    /// Called with each inbound chunk of bytes from the server.
    var onReceive: ((UnsafeRawBufferPointer) -> Void)?

    func connect() {
        connectionTask = Task { try await runWireGuard() }
    }

    /// RAW-encodes `data` and writes it to the server.
    func write(_ data: any RAW_convertible) async throws {
        guard let channel = try await interface?.getChannel() else { return }
        var dataCount = 0; data.RAW_encode(count: &dataCount)
        var buffer = ByteBufferAllocator().buffer(capacity: dataCount)
        buffer.withUnsafeMutableWritableBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            _ = data.RAW_encode(dest: base.assumingMemoryBound(to: UInt8.self))
        }
        buffer.moveWriterIndex(forwardBy: dataCount)
        try WGInterface<KCPChannels>.write(channel: channel, publicKey: myPublicKey, data: buffer)
    }

    // MARK: - WireGuard lifecycle

    @MainActor
    private func runWireGuard() async throws {
        _ = try await withThrowingTaskGroup(of: Void.self) { group in
            let fifo = FIFO<ByteBuffer, Swift.Error>()
            let peers: [PeerInfo] = [
                PeerInfo(publicKey: myPublicKey, sharedKey: nil,
                         ipAddress: serverIP, port: serverPort,
                         internalKeepAlive: nil, inboundData: fifo)
            ]
            let interface = try WGInterface<KCPChannels>(
                staticPrivateKey: myPrivateKey,
                mtu: 1400,
                initialConfiguration: peers,
                logLevel: .info,
                listeningPort: 0)                       // 0 = ephemeral local port

            group.addTask { try await interface.run() }
            try await interface.waitForChannelInit()

            // Consume inbound data and forward it to the receiver.
            group.addTask {
                let iterator = fifo.makeAsyncConsumer()
                while !Task.isCancelled {
                    if let data = try await iterator.next(whenTaskCancelled: .finish) {
                        data.withUnsafeReadableBytes { ptr in
                            self.onReceive?(ptr)
                        }
                    }
                }
            }

            try await group.waitForAll()
        }
    }
}
```

The server must have the **client's WireGuard public key** listed in its `peer-config.json` (see "Running a Tessera server"), or it will not accept the connection.

### The receiver

Inbound bytes arrive as RAW-serialized NOSTR messages. Rather than parsing everything from scratch, implement `TesseraClientReceiver` (from `tessera-core`) and route each inbound chunk straight into it. The protocol extension handles: decoding `EVENT` messages, ignoring events superseded by deletions, following replaceable-key references (queueing follow-up `REQ`s), and dispatching each event to the right model.

```swift
import tessera_core
import nostr_kit_swift

/// Dispatches inbound events to the client's models.
final class MyReceiver: TesseraClientReceiver {
    var deletionEventIds: [NOSTR_id: NOSTR_date] = [:]
    var references: [ReplaceableKey: NOSTR_id] = [:]
    var referenceNeeds: [String: [Filter]] = [:]
    var models: [any TesseraCompliantModel] = []

    init(models: [any TesseraCompliantModel]) {
        self.models = models
    }
}
```

Wire it up in the connection wrapper: `onReceive = { ptr in try? receiver.receive(ptr: ptr) }` for example.

### A data model

For each kind of data the app displays, create a model conforming to `TesseraCompliantModel`. The model declares the content type of the events it holds, lists the subscription id(s) it cares about, and gets automatic storage + latest/history indexing:

```swift
import Combine
import tessera_core
import nostr_kit_swift

/// The event content type — must conform to `NOSTR_event_content`.
/// `StringContent` (a UTF-8 string) is provided by nostr-kit-swift; a custom
/// content type can carry structured data over the wire.
final class MyModel: ObservableObject, TesseraCompliantModel {
    typealias ContentType = StringContent

    var latestByReplaceableKey: [ReplaceableKey: NOSTR_id] = [:]
    var historyByReplaceableKey: [ReplaceableKey: [NOSTR_id]] = [:]

    @Published var modelStorage: [NOSTR_id: UnsignedEvent<ContentType>] = [:]

    /// Registration of the filter(s) used to fetch this model's events.
    var subscriptionIDs = ["mySubscription"]
}
```

The `TesseraCompliantModel` extension provides ready-made helpers: `latestEvents()` (current value of every replaceable key), `clearCache()`, `delete(id:)`, and `decodeEventAndUpsert(ptr:)` (called internally by the receiver).

### Subscribing (REQ)

To receive events, send a `NOSTR_message_REQ` containing one or more `Filter`s. The server replies with every matching event (past and live) followed by an `EOSE` marking the end of the historical batch. The model's `subscriptionIDs` must contain the subscription id used in the REQ, and the `user` must be the client's Nostr public key:

```swift
func subscribe(server: TesseraClient, to model: MyModel, myNostrPublicKey: PublicKey) {
    // Match all events of one kind for the application.
    let filter = Filter(
        applications: [1],                                        // the application id
        kinds: [createKind(accessLevel: 1, kind: 17_000).RAW_native()]
    )
    let req = NOSTR_message_REQ(
        subscriptionID: model.subscriptionIDs[0],
        filters: [filter],
        from: myNostrPublicKey,
        fetchHistory: true)                                       // true → also fetch stored history
    Task { try await server.write(req) }
}
```

Conditions within one filter are AND'd; multiple filters are OR'd. `limit` applies to the initial query only.

To end a subscription, send `NOSTR_message_CLOSE(subscriptionID: mySubscription)` to tell the server to stop sending.

### Sending events

Build an `UnsignedEvent` with the event content, sign it with the client's Nostr (Ed25519) key, wrap it in an `EVENT` message, and write it:

```swift
// Derive the Nostr signing key from the WireGuard key, or load it from the keychain:
//   let (myNostrPublicKey, myNostrPrivateKey) = try Ed25519.generateKeys(secretKey: wireGuardPrivateKey)

let unsigned = try UnsignedEvent(
    publicKey: myNostrPublicKey,
    tags: [DTag(value: "unique-record-id")],            // d-tag → parameterized replaceable event
    application: 1,                                     // the application id
    kind: createKind(accessLevel: 1, kind: 17_000),     // kinds live inside access-level blocks
    content: myContent)
let signedEvent = try unsigned.sign(as: myNostrPrivateKey)
let message = NOSTR_message_EVENT(subscriptionID: "mySubscription", event: signedEvent)   // sub id is ignored by the server for writes
try await server.write(message)
```

The server verifies the signature, checks the author's write access (against the profile's access levels), and stores the event. It answers with a `NOSTR_message_OK`, or a `NOTICE` if the event was rejected.

### Deleting events

Send a kind-5 deletion event that references the event to delete by id. The server only honors deletions of events authored by that key; the receiver then removes the event from every model:

```swift
let deletion = try UnsignedEvent(
    publicKey: myNostrPublicKey,
    tags: [EventRefTag(value: eventToDelete.id)],
    application: 1,
    kind: 5,
    content: ByteBuffer())
let signedDeletion = try deletion.sign(as: myNostrPrivateKey)
let deletionMessage = NOSTR_message_EVENT(subscriptionID: model.subscriptionIDs[0], event: signedDeletion)
try await server.write(deletionMessage)
```

### Message reference

| Message | Direction | Purpose |
|---|---|---|
| `NOSTR_message_REQ` | client → server | Subscribe with one or more `Filter`s; receive history + live events |
| `NOSTR_message_EVENT` | both | Send an event to be stored, or receive a stored event |
| `NOSTR_message_CLOSE` | client → server | End a subscription |
| `NOSTR_message_EOSE` | server → client | End of the initial (historical) batch for a subscription |
| `NOSTR_message_NOTICE` | server → client | Error/notice text (e.g. a rejected event) |
| `NOSTR_message_OK` | server → client | Acknowledgment of an event submission |

### Key concepts

- **Application id** — every event carries a 2-byte application id. The server scopes storage/permissions around it; a client application uses a fixed id for its lifetime.
- **Kinds & access levels** — kinds are not arbitrary: they are created within an access-level block via `createKind(accessLevel:kind:)` (e.g. `createKind(accessLevel: 1, kind: 17_000)`). The server rejects writes when the author's profile lacks the corresponding access level.
- **Replaceable events** — a `DTag` on an event makes it a parameterized replaceable event; the server keeps the newest revision and clients track "latest" vs "history" automatically.
- **Signatures** — events must be signed (`Ed25519`) by the client's Nostr key; the server drops events with invalid signatures.

---

## Project layout

- **`tessera`** — executable: the `tessera-service` CLI and the daemon (`TesseraService`, `Sources/tessera/Service/`).
- **`tessera-core`** — library: the LMDB database layer (`Sources/tessera-core/Database/`) and the client-side helpers (`Sources/tessera-core/ClientReceiver/`).
- **`tessera-tests`** — `Tests/tessera-tests/tests.swift`, the Swift Testing suite.

For more detail (database schema, access levels, kind categories, write rules), see `AGENT.md` in this repository.

