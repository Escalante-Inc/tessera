# tessera

Tessera is a Swift server for NOSTR event applications. It ships as a single executable that is **both a long-running daemon and a CLI tool**. The daemon acts as a central connection point: it listens on a WireGuard interface (using [wireguard-swift](https://github.com/tannerdsilva/wireguard-swift)), accepts signed NOSTR events and subscription requests from **other tessera nodes and end-user applications**, stores everything in a local LMDB database, and fans events out to matching subscriptions.

Clients and servers talk to each other with **signed NOSTR events** serialized with the [RAW](https://github.com/tannerdsilva/rawdog) byte library, wrapped in NOSTR `REQ` / `EVENT` / `CLOSE` messages over the WireGuard channel. The `tessera-core` Swift package also provides the client-side building blocks — a ready-made connection (`TesseraClient`), a message/wire-protocol façade (`TesseraSession`), a receiver (`TesseraClientReceiverStore`), and caching model base classes (`TesseraModel`) — so a client can be built entirely on top of them.

---

## Installation

```bash
git clone https://github.com/bwyma1/tessera.git

cd tessera
swift build
```

If the YubiKey/smartcard commands are needed, build with the provided script so the binary is re-signed with the SmartCard entitlement (`com.apple.security.smartcard`):

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

The server only accepts WireGuard connections from peers listed in its configuration file (`peer-config.json`, defaulting to the home directory). Add a peer by its public key:

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
- `--configuration-path` — where `peer-config.json` lives. Defaults to the home directory.

The daemon keeps running indefinitely: it initializes the WireGuard interface, listens for incoming encrypted traffic from configured peers, decodes NOSTR messages, scribes events to the database, answers subscription requests, and pushes live events to subscribers. Use `--help` on any subcommand for the full option list.

---

## Building a Tessera client

The complete guide to building a client application — from the mental model and key concepts through adding the dependency to writing the connection, receiver, model, and session — lives in [SETUP.md](docs/SETUP.md).

---

## Project layout

- **`tessera`** — executable: the `tessera-service` CLI and the daemon (`TesseraService`, `Sources/tessera/Service/`).
- **`tessera-core`** — library: the LMDB database layer (`Sources/tessera-core/Database/`) and the client-side helpers — the connection/session wrappers (`Sources/tessera-core/ClientConnection/`) and the receiver (`Sources/tessera-core/ClientReceiver/`).
- **`tessera-tests`** — `Tests/tessera-tests/tests.swift`, the Swift Testing suite.

For more detail (database schema, access levels, kind categories, write rules), see `AGENT.md` in this repository.

