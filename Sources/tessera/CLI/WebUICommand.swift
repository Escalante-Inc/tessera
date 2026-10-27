import Foundation
import ArgumentParser
import tessera_core
import bedrock
import Logging
import RAW
import RAW_base64
#if canImport(WebUI)
import WebUI

extension CLI {

	/// Hosts the tessera admin dashboard as a webui server (no-webui runtime).
	///
	/// Serves the same information as `tessera-service admin` — users and their
	/// activity, event statistics, configured peer relays, recent peer
	/// transactions, and access levels — over HTTP + WebSocket at
	/// http://<host>:<port>.
	struct WebUI:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"webui",
			abstract:"Host a webui admin dashboard for this relay."
		)

		@Option(help:"the path to the database directory, defaults to the user's home directory")
		var databasePath:bedrock.Path = CLI.defaultDBBasePath()

		@Option(help:"the path to the configuration directory containing peer-config.json, defaults to the user's home directory")
		var configurationPath:bedrock.Path = Path(FileManager.default.homeDirectoryForCurrentUser.path)

		@Option(help:"the address to bind the dashboard to (default: 127.0.0.1)")
		var host:String = "127.0.0.1"

		@Option(help:"the port to serve the dashboard on (default: 9777)")
		var port:Int = 9777

		@Option(help:"a user is 'active' when their most recent event is newer than this many days (default: 7)")
		var activityWindow:Int = 7

		@Option(help:"seconds between live-update pushes to connected browsers (0 disables; default: 15)")
		var pollInterval:Int = 15

		@Option(help:"base64 admin secret key (RAW_dh25519.PrivateKey) used to sign user events; enables add/remove in the Users section. Omit for a read-only dashboard.")
		var adminKey:String? = nil

		@Option(help:"the logging verbosity for the dashboard (default: info)")
		var logLevel:Logger.Level = .info

		func run() async throws {
			let databaseFile = databasePath.appendingPathComponent("tessera.mdb")
			guard FileManager.default.fileExists(atPath: databaseFile.path()) else {
				throw ValidationError("No tessera database found at \(databaseFile.path())\n(pass --database-path pointing at the relay's database directory)")
			}
			if let adminKey {
				guard let bytes = try? RAW_base64.decode(adminKey), bytes.count == 32 else {
					throw ValidationError("--admin-key must be a base64-encoded 32-byte RAW_dh25519.PrivateKey")
				}
			}
			let db = try TesseraDB.openTessera(base: databasePath, memoryMapSize: size_t(databasePath.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .info)
			let server = try AdminWebUIServer(db: db, databasePath: databasePath, configurationPath: configurationPath, activityWindowDays: activityWindow, host: host, port: port, pollInterval: TimeInterval(pollInterval), adminKey: adminKey, logLevel: logLevel)
			try await server.run()
		}
	}
}

#endif
