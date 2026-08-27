# Tessera Client Setup

This guide walks through building a Tessera client application from scratch. It assumes no prior knowledge of Tessera, WireGuard, or the NOSTR wire protocol. By the end, a working client will exist that connects to a Tessera server, subscribes to events, publishes events, and deletes events.

[The Mental Model](#the-mental-model)

[Key Concepts](#key-concepts)

[One-Time Server Setup](#one-time-server-setup)

[Add Tessera to the App](#add-tessera-to-the-app)

[The Four Client-Side Pieces](#the-four-client-side-pieces)

[Write the Client](#write-the-client)

[Reference: Full Lifecycle](#reference-full-lifecycle)

---

## The mental model

A Tessera server is a NOSTR event store. It listens on a **WireGuard** tunnel, accepts signed **NOSTR events** and **subscriptions** from clients, stores events in LMDB, and pushes matching events back to subscribed clients.

An app is a *peer* on that WireGuard tunnel. No HTTP or JSON is involved — everything is a RAW-serialized NOSTR message (`REQ`, `EVENT`, `EOSE`, `NOTICE`, `CLOSE`) travelling over an encrypted UDP tunnel.

The library hides almost all of that. From the app's point of view the flow is:

```
build a connection → connect → subscribe (hear events) → publish (send events) → disconnect
```

Four client-side pieces make this work, and the library provides all of them:

| Piece | Provided by | What it does |
|---|---|---|
| Connection wrapper | `TesseraClient` | Owns the WireGuard tunnel (connect / disconnect / write) |
| Receiver | `TesseraClientReceiverStore` | Decodes inbound messages, routes events to models |
| Data model | `TesseraModel<ContentType>` (subclass) | Caches events, tracks latest vs history |
| Session (glue) | `TesseraSession` | Ties the above together: `subscribe` / `publish` / `delete` / `unsubscribe` |

---

## Key concepts

There are five ideas worth understanding before writing code.

### Two key pairs

- **WireGuard key pair** — identifies the app at the *transport* level. The server only lets listed WireGuard public keys connect.
- **Nostr (Ed25519) key pair** — identifies the app at the *data* level. Every published event is signed with it, and the server checks it against the stored user profile.

In Tessera these are linked: the Nostr key is *derived* from the WireGuard private key:

```swift
let (myNostrPublicKey, myNostrPrivateKey) = try Ed25519.generateKeys(secretKey: wireGuardPrivateKey)
```

The server's `create-unbounded-admin` registration derives the Nostr key the exact same way, so deriving on the client makes signed events match the stored profile. A different derivation means the server rejects the writes.

### Application id

A `UInt16` naming the app's data domain. The server scopes storage and permissions around it. Pick one fixed value for the app's lifetime:

```swift
let applicationID: UInt16 = 1
```

### Kinds and access levels

A kind is the *type* of event. Tessera does not allow arbitrary kind numbers: kinds live inside access-level blocks created with `createKind(accessLevel:kind:)`:

```swift
let kind = createKind(accessLevel: 1, kind: 17_000)   // e.g. the "menu items" kind
```

Two rules of thumb:

- **Kinds below 40,000 need no access level** — any registered user can read/write them. The examples use `kind 3000` for this reason.
- Kinds created with `createKind` live in the 40,000+ range and require the user profile to have the matching access level, or the server rejects the write with a NOTICE.

### Subscriptions (REQ / EOSE)

A subscription is a **filter** under a **subscription id** (a client-chosen string). The server replies with all *stored* matching events, then an `EOSE` ("end of stored events" — initial history is done). After that, any *new* matching event is pushed live under the same subscription id until the subscription is closed.

The subscription id must be **unique within the connection** and must match what the model declares (see [Add Tessera to the App](#add-tessera-to-the-app)).

### Events and signatures

An event = public key + timestamp + tags + application + kind + content + **id** (SHA-256 of the fields) + **signature**. The id is never computed by hand — `UnsignedEvent` computes it from the fields, then `.sign(as:)` signs the event with the Nostr private key.

---

## One-time server setup

A reachable server is required before any client code. This is setup, not app code — done once, or by whoever runs the server.

### Build the server

```bash
git clone https://github.com/bwyma1/tessera.git
cd tessera
swift build            # binary at .build/debug/tessera
```

### Generate keys

```bash
.build/debug/tessera generate-keys     # the server's WireGuard keypair
```

Save both values. The **public** key is what the app will be configured with; the **private** key starts the daemon.

### Register the app as a peer and a user

The server must (a) allow the app's WireGuard public key to connect, and (b) know the app's Nostr identity with access rights. Both use the server CLI with the *app's* keys:

```bash
# The app's WireGuard keypair (same generate-keys command)
.build/debug/tessera generate-keys
#   → save the client public + private key

# 1. Allow the client's WireGuard public key as a peer
.build/debug/tessera config add --keep-alive 15 "<client public key>"

# 2. Register the client's Nostr identity with full access levels
#    (pass the client's WG PRIVATE key; the server derives the Nostr key from it)
.build/debug/tessera create-unbounded-admin "<client private key>" "MyApp"
```

> Real deployments control write access per-kind instead of using an unbounded admin; `create-unbounded-admin` is the simplest way to get a working client quickly.

### Start the daemon

```bash
.build/debug/tessera run \
  --database-path ~/tessera_lmdb \
  --configuration-path ~/ \
  <port> \
  "<server private key>"
```

The app connects to `serverIP:<port>`.

---

## Add Tessera to the app

In the app's `Package.swift`:

```swift
// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "MyApp",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(url: "https://github.com/bwyma1/tessera", branch: "main"),
        .package(url: "https://github.com/bwyma1/nostr-kit-swift", branch: "main"),
        .package(url: "https://github.com/tannerdsilva/rawdog.git", "21.0.0"..<"22.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", "2.81.0"..<"3.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "MyApp",
            dependencies: [
                .product(name: "tessera-core", package: "tessera"),
                .product(name: "nostr-kit-swift", package: "nostr-kit-swift"),
                .product(name: "RAW", package: "rawdog"),
                .product(name: "RAW_dh25519", package: "rawdog"),
                .product(name: "RAW_ed25519", package: "rawdog"),
                .product(name: "RAW_base64", package: "rawdog"),
                .product(name: "NIO", package: "swift-nio"),
            ]
        ),
    ]
)
```

`tessera-core` pulls in the WireGuard stack (`wireguard-userspace-nio`, `bedrock_fifo`, `swift-log`) **transitively** — those are not declared directly.

---

## The four client-side pieces

### The connection (`TesseraClient`)

`TesseraClient` is the ready-made connection wrapper. It creates the WireGuard interface, waits for the UDP channel to bind, drains the peer's inbound FIFO on a background task, and exposes `write(_:)` which RAW-encodes any message into the tunnel. No NIO or WireGuard plumbing appears in the app.

Build a `TesseraClientConfiguration` — typed keys:

```swift
import tessera_core
import RAW_dh25519

let configuration = TesseraClientConfiguration(
    serverIP: "127.0.0.1",                 // the server's address
    serverPort: 51820,                     // the server's `my-port`
    serverPublicKey: serverPublicKey,      // the server's WireGuard public key
    myPrivateKey: myPrivateKey,            // this client's WireGuard private key
    logLevel: .info
)
let client = TesseraClient(configuration: configuration)
```

or base64-key convenience (returns `nil` if either key is not valid 32-byte base64):

```swift
let configuration = TesseraClientConfiguration(
    serverIP: "127.0.0.1",
    serverPort: 51820,
    serverPublicKeyBase64: "...server public key...",
    myPrivateKeyBase64: "...client private key..."
)
```

The server must list the **client's WireGuard public key** in its `peer-config.json` (see [Register the app as a peer and a user](#register-the-app-as-a-peer-and-a-user)), or it will not accept the connection.

### The data model (`TesseraModel`)

For each kind of data the app displays, subclass `TesseraModel<ContentType>`. The base class declares all the backing storage — `modelStorage`, `latestByReplaceableKey`, `historyByReplaceableKey` — so a model only configures its content type and subscription id(s):

```swift
import Combine
import tessera_core
import nostr_kit_swift

/// The event content type — must conform to `NOSTR_event_content`.
/// `StringContent` (a UTF-8 string) is provided by nostr-kit-swift; a custom
/// content type can carry structured data over the wire.
final class MenuModel: TesseraModel<StringContent>, ObservableObject {
    /// The subscription id used to fetch this model's events.
    /// NOTE: `subscriptionIDs` is a mutable stored property; configure it in `init`.
    override init() {
        super.init()
        subscriptionIDs = ["menuSubscription"]
    }
}
```

`TesseraCompliantModel` (the protocol `TesseraModel` conforms to) provides ready-made helpers: `latestEvents()` (current value of every replaceable key), `clearCache()`, `delete(id:)`, and `decodeEventAndUpsert(ptr:)` (called internally by the receiver).

### The receiver (`TesseraClientReceiverStore`)

Inbound bytes arrive as RAW-serialized NOSTR messages. Instead of parsing them by hand, attach a receiver to the session; the session decodes each message with `NOSTR_message.decode` and dispatches it. `TesseraClientReceiverStore` is a concrete receiver with pre-declared storage — instantiate it and attach the models:

```swift
import tessera_core

let receiver = TesseraClientReceiverStore()
receiver.models.append(menuModel)
```

The receiver's protocol extension handles: decoding `EVENT` messages, ignoring events superseded by deletions, following replaceable-key references (queueing follow-up `REQ`s), and dispatching each event to the right model.

### The session (`TesseraSession`)

`TesseraSession` ties the connection, receiver, and message protocol together:

```swift
import tessera_core

let session = TesseraSession(
    client: client,                    // the TesseraClient from earlier
    receiver: receiver,                // the TesseraClientReceiverStore
    application: 1,                    // this client's application id
    myNostrPublicKey: myNostrPublicKey // the derived Nostr public key
)

// Optional callbacks for server control messages:
session.onNotice = { text in print("server notice: \(text)") }
session.onEOSE = { eose in print("history complete for \(String(eose.subscriptionID))") }

try await session.connect()
```

`connect()` wires the client's inbound bytes into the session's decoder and establishes the tunnel. `disconnect()` tears it down. Application code then works with `subscribe`, `publish`, `delete`, and `unsubscribe` — the session builds and sends the underlying `REQ` / `EVENT` / `CLOSE` messages.

---

## Write the client

This is the complete client flow, assembled from the pieces above.

### Constants and identity

```swift
import Foundation
import NIO
import nostr_kit_swift
import RAW
import RAW_dh25519
import RAW_ed25519
import RAW_base64
import tessera_core

// Fixed identity values (see Key concepts).
let applicationID: UInt16 = 1
let eventKind: UInt32 = 3000                  // < 40_000 → no access level needed
let subscriptionID = "my-subscription"

// Base64 client private key → memory-guarded WireGuard key.
let rawKey = try RAW_base64.decode("...base64 client private key...")
guard rawKey.count == 32 else { throw TesseraClientError.notConnected }
let myPrivateKey: MemoryGuarded<RAW_dh25519.PrivateKey> = try rawKey.withUnsafeBufferPointer { ptr in
	guard let value = MemoryGuarded<RAW_dh25519.PrivateKey>.init(RAW_accessed: ptr) else {
		throw NOSTR_message_error.badDecode
	}
	return value
}

// Derive the Nostr identity used to sign events.
let (myNostrPublicKey, myNostrPrivateKey) = try Ed25519.generateKeys(secretKey: myPrivateKey)
```

### Connect and subscribe

```swift
let configuration = TesseraClientConfiguration(
    serverIP: "192.168.1.50",          // the server
    serverPort: 51820,                 // the daemon's <port>
    serverPublicKeyBase64: "...server public key...",
    myPrivateKeyBase64: "...client private key..."
)
let client = TesseraClient(configuration: configuration)

let receiver = TesseraClientReceiverStore()
let model = MenuModel()
receiver.models.append(model)

let session = TesseraSession(
    client: client,
    receiver: receiver,
    application: applicationID,
    myNostrPublicKey: myNostrPublicKey
)

try await session.connect()

let filter = Filter(applications: [applicationID], kinds: [eventKind])
try await session.subscribe(subscriptionID: subscriptionID, filters: [filter])
```

From this point, matching events land in `model.modelStorage`, and the UI is driven from the model.

### Publish

```swift
let unsigned = try UnsignedEvent(
    publicKey: myNostrPublicKey,
    tags: [DTag(value: "item-42")],            // d-tag → replaceable event (latest wins)
    application: applicationID,
    kind: eventKind,
    content: ByteBuffer(string: "{\"name\":\"Burger\",\"price\":9.5}")
)
let signedEvent = try unsigned.sign(as: myNostrPrivateKey)
try await session.publish(signedEvent)
```

If the app's own subscription filter matches this event, the server pushes it straight back — publishing then reading from the model is a normal round-trip.

### Delete

```swift
try await session.delete(eventID: someEventID, signedBy: myNostrPrivateKey)
```

One line — `TesseraSession` builds the kind-5 deletion event, signs it, and publishes it. The server removes the event, and the receiver removes it from the app's models automatically.

### Disconnect

```swift
try await session.unsubscribe(subscriptionID: subscriptionID)
await session.disconnect()
```

---

## Reference: full lifecycle

```swift
let configuration = TesseraClientConfiguration(
    serverIP: "127.0.0.1", serverPort: 51820,
    serverPublicKeyBase64: serverPubKey, myPrivateKeyBase64: myPrivKey
)!
let (nostrPub, nostrPriv) = try Ed25519.generateKeys(secretKey: configuration.myPrivateKey)

let receiver = TesseraClientReceiverStore()
let model = MenuModel()
receiver.models.append(model)

let session = TesseraSession(client: TesseraClient(configuration: configuration),
                             receiver: receiver,
                             application: 1,
                             myNostrPublicKey: nostrPub)

try await session.connect()                                    // 1. tunnel up
try await session.subscribe(subscriptionID: "menu", filters: [menuFilter])   // 2. hear events
try await session.publish(event)                               // 3. send events
try await session.delete(eventID: id, signedBy: nostrPriv)     // 4. remove events
try await session.unsubscribe(subscriptionID: "menu")
await session.disconnect()                                     // 5. done
```

