import Foundation
import ArgumentParser
import tessera_core
import bedrock
import RAW
import RAW_base64
import RAW_dh25519
import QuickLMDB
import Logging

extension CLI {

	/// Read-only administrative inspection of a running (or stopped) tessera relay.
	///
	/// Opens the relay's LMDB database in-place and reports on users, event
	/// statistics, configured peer relays, and recent peer transactions. Safe to
	/// run while the relay is live: reads never block the writer.
	struct Admin:ParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"admin",
			abstract:"Inspect a tessera relay database (users, stats, peers, transactions).",
			subcommands:[Users.self, Stats.self, Peers.self, Transactions.self, AccessLevels.self]
		)

		// MARK: shared helpers

		/// Opens the tessera database at the given base path for reading. Fails with a
		/// clear message when no database exists there (instead of creating one).
		static func openAdminDatabase(_ databasePath:Path) throws -> TesseraDB {
			let databaseFile = databasePath.appendingPathComponent("tessera.mdb")
			guard FileManager.default.fileExists(atPath: databaseFile.path()) else {
				throw ValidationError("No tessera database found at \(databaseFile.path())\n(pass --database-path pointing at the relay's database directory)")
			}
			return try TesseraDB.openTessera(base: databasePath, memoryMapSize: size_t(databasePath.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .info)
		}

		/// Renders a columnar table with a leading header row.
		static func printTable(headers:[String], rows:[[String]]) {
			var widths = headers.map { $0.count }
			for row in rows {
				for (index, cell) in row.enumerated() where index < widths.count {
					widths[index] = max(widths[index], cell.count)
				}
			}
			let render = { (cells:[String]) -> String in
				cells.enumerated().map { (index, cell) in
					let width = index < widths.count ? widths[index] : cell.count
					return cell.count < width ? cell.padding(toLength: width, withPad: " ", startingAt: 0) : cell
				}.joined(separator: "  ")
			}
			print(render(headers))
			print(widths.map { String(repeating: "-", count: $0) }.joined(separator: "  "))
			for row in rows {
				print(render(row))
			}
		}

		static func formatDate(_ date:Foundation.Date?) -> String {
			guard let date else { return "-" }
			return date.formatted(date: .abbreviated, time: .shortened)
		}

		/// Truncates a base64 key for table display.
		static func shortKey(_ key:String, length:Int = 14) -> String {
			return key.count <= length ? key : key.prefix(length) + "…"
		}

		static func userStatus(lastActivity:Foundation.Date?, windowDays:Int) -> String {
			guard let lastActivity else { return "never active" }
			let window = TimeInterval(windowDays) * 86_400
			return (Date().timeIntervalSince(lastActivity) <= window) ? "active" : "inactive"
		}

		// MARK: subcommands

		/// Lists registered users with access levels and activity status.
		struct Users:ParsableCommand {
			static let configuration = CommandConfiguration(abstract:"List registered users and whether they are currently active.")

			@Option(help:"the path to the database directory, defaults to the user's home directory")
			var databasePath:bedrock.Path = CLI.defaultDBBasePath()

			@Option(help:"a user is 'active' when their most recent event is newer than this many days (default: 7)")
			var window:Int = 7

			func run() throws {
				let db = try CLI.Admin.openAdminDatabase(databasePath)
				let users = try db.adminListUsers()
				guard !users.isEmpty else {
					print("No users registered in \(databasePath.path()).")
					return
				}
				print("Users (\(users.count), activity window: \(window) day(s))")
				var rows:[[String]] = []
				for user in users {
					rows.append([
						user.name ?? "(unnamed)",
						CLI.Admin.shortKey(user.publicKey),
						AdminUserInfo.format(user.readAccessLevels),
						AdminUserInfo.format(user.writeAccessLevels),
						String(user.eventCount),
						formatDate(user.lastActivity),
						userStatus(lastActivity:user.lastActivity, windowDays:window)
					])
				}
				printTable(headers:["NAME", "PUBLIC KEY", "READ", "WRITE", "EVENTS", "LAST SEEN", "STATUS"], rows:rows)
			}
		}

		/// Prints aggregate statistics over the event database.
		struct Stats:ParsableCommand {
			static let configuration = CommandConfiguration(abstract:"List statistics about the stored events.")

			@Option(help:"the path to the database directory, defaults to the user's home directory")
			var databasePath:bedrock.Path = CLI.defaultDBBasePath()

			func run() throws {
				let db = try CLI.Admin.openAdminDatabase(databasePath)
				var stats = try db.adminEventStats()
				let databaseFile = databasePath.appendingPathComponent("tessera.mdb")
				if let attributes = try? FileManager.default.attributesOfItem(atPath: databaseFile.path()), let size = attributes[.size] as? Int64 {
					stats = stats.withDatabaseFileSize(size)
				}

				let byteFormatter = ByteCountFormatter()
				byteFormatter.countStyle = .binary

				print("Event statistics")
				print("  Total events:        \(stats.totalEvents)")
				print("  Registered users:    \(stats.userCount)")
				print("  Access levels:       \(stats.accessLevelCount)")
				print("  Deletion events:     \(stats.deletionCount)")
				print("  Replaceable events:  \(stats.replaceableEvents) (\(stats.replaceableRevisions) revisions)")
				print("  Database size:       \(byteFormatter.string(fromByteCount: stats.databaseFileSize))")
				print("")
				print("  Last 24 hours:       \(stats.last24h)")
				print("  Last 7 days:         \(stats.last7d)")
				print("  Oldest event:        \(formatDate(stats.oldestEvent))")
				print("  Newest event:        \(formatDate(stats.newestEvent))")

				if !stats.perKind.isEmpty {
					print("")
					print("  Events per kind:")
					let kindRows = stats.perKind.sorted { $0.value > $1.value }.map { ($0.key, $0.value) }
					for (kind, count) in kindRows {
						let label = kind == Int(TesseraKinds.user.value) ? " (users)" : kind == Int(TesseraKinds.accessLevel.value) ? " (access levels)" : kind == 5 ? " (deletions)" : ""
						print("    \(String(kind).padding(toLength: 10, withPad: " ", startingAt: 0)) \(String(count).padding(toLength: 10, withPad: " ", startingAt: 0))\(label)")
					}
				}
				if !stats.perApplication.isEmpty {
					print("")
					print("  Events per application:")
					for (application, count) in stats.perApplication.sorted(by: { $0.key < $1.key }) {
						print("    \(application): \(count)")
					}
				}
				if !stats.perAuthor.isEmpty {
					print("")
					print("  Top authors:")
					for (author, count) in stats.perAuthor.sorted(by: { $0.value > $1.value }).prefix(10) {
						print("    \(shortKey(author))  \(count)")
					}
				}
			}
		}

		/// Lists the peers configured for this relay, marking tessera relays vs. applications.
		struct Peers:ParsableCommand {
			static let configuration = CommandConfiguration(abstract:"List configured peer relays and applications.")

			@Option(help:"the path to the configuration directory containing peer-config.json, defaults to the user's home directory")
			var configurationPath:bedrock.Path = Path(FileManager.default.homeDirectoryForCurrentUser.path)

			func run() throws {
				let jsonURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
				guard FileManager.default.fileExists(atPath: jsonURL.path) else {
					throw ValidationError("No peer configuration found at \(jsonURL.path)")
				}
				let cfg = try loadConfig(from: jsonURL)
				guard !cfg.peers.isEmpty else {
					print("No peers configured in \(jsonURL.path).")
					return
				}
				let tesseraCount = cfg.peers.filter { $0.isTessera }.count
				print("Peers (\(cfg.peers.count); \(tesseraCount) tessera relay(s), \(cfg.peers.count - tesseraCount) application(s))")
				var rows:[[String]] = []
				for peer in cfg.peers {
					rows.append([
						CLI.Admin.shortKey(String(RAW_base64.encode(peer.publicKey)), length: 24),
						peer.isTessera ? "tessera relay" : "application",
						peer.endpoint.map { String(describing: $0) } ?? "-",
						peer.internalKeepAlive.map { "\($0.nanoseconds / 1_000_000_000)s" } ?? "-"
					])
				}
				printTable(headers:["PUBLIC KEY", "TYPE", "ENDPOINT", "KEEP-ALIVE"], rows:rows)
			}
		}

		/// Prints recent peer transactions recorded by the running relay.
		struct Transactions:ParsableCommand {
			static let configuration = CommandConfiguration(abstract:"List recent transactions with peer relays.")

			@Option(help:"the path to the database directory containing peer-transactions.jsonl, defaults to the user's home directory")
			var databasePath:bedrock.Path = CLI.defaultDBBasePath()

			@Option(help:"number of recent transactions to display (default: 20)")
			var limit:Int = 20

			func run() throws {
				let log = PeerTransactionLog(base: databasePath, logLevel: .info)
				let records = log.read(limit: limit)
				guard !records.isEmpty else {
					print("No peer transactions recorded yet in \(PeerTransactionLog.filePath(base: databasePath).path()).")
					print("Records appear once the relay is running and peers exchange events, requests, or sync rounds.")
					return
				}
				print("Recent peer transactions (\(records.count) most recent)")
				var rows:[[String]] = []
				for record in records {
					rows.append([
						record.timestamp.formatted(date: .abbreviated, time: .standard),
						record.direction,
						record.type,
						shortKey(record.peer, length: 14),
						record.detail
					])
				}
				printTable(headers:["TIME", "DIRECTION", "TYPE", "PEER", "DETAIL"], rows:rows)
			}
		}

		/// Lists all kind-1 access level events.
		struct AccessLevels:ParsableCommand {
			static let configuration = CommandConfiguration(abstract:"List the access levels defined on this relay.")

			@Option(help:"the path to the database directory, defaults to the user's home directory")
			var databasePath:bedrock.Path = CLI.defaultDBBasePath()

			func run() throws {
				let db = try CLI.Admin.openAdminDatabase(databasePath)
				let levels = try db.adminListAccessLevels()
				guard !levels.isEmpty else {
					print("No access levels defined in \(databasePath.path()).")
					return
				}
				var rows:[[String]] = []
				for level in levels.sorted(by: { $0.level < $1.level }) {
					rows.append([
						String(level.level),
						level.name,
						formatDate(level.date),
						shortKey(level.author)
					])
				}
				print("Access levels (\(levels.count))")
				printTable(headers:["LEVEL", "NAME", "CREATED", "AUTHOR"], rows:rows)
			}
		}
	}
}
