import Foundation
import RAW
import RAW_dh25519
import RAW_base64
import RAW_ed25519
import NIO
import Logging
import ArgumentParser
import ServiceLifecycle
import bedrock

@main
struct CLI:AsyncParsableCommand {
	static func defaultDBBasePath() -> Path {
		return Path(FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("calendar_app_service_lmdb").path)
	}
	
	static let configuration = CommandConfiguration(
		commandName:"calendar-app-service",
		abstract:"a server side program for the calendar app",
		subcommands:[
				Run.self,
				GenerateKeys.self,
				Config.self
			]
		)
	
	struct GenerateKeys:ParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"Generate a new nostr note key pair."
		)
		
		@Argument(help:"My private key for the Wireguard interface.")
		var myPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
		
		func run() throws {
			let (publicKey, privateKey) = try Ed25519.generateKeys(secretKey: myPrivateKey)
			let publicKeyBase64 = String(RAW_base64.encode(publicKey))
			let privateKeyBase64 = String(RAW_base64.encode(privateKey))
			print("Public Key: \(publicKeyBase64)")
			print("Private Key: \(privateKeyBase64)")
		}
	}
	
	struct Run:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName: "run",
			abstract: "Runs the server side calendar service."
		)
		
		@Option(help:"the path to the database directory, defaults to the user's home directory")
		var databasePath:bedrock.Path = CLI.defaultDBBasePath()
		@Option(help:"the path to the configuration directory, defaults to the user's home directory")
		var configurationPath:bedrock.Path = Path(FileManager.default.homeDirectoryForCurrentUser.path)

		@Argument(help: "The port number that I am is listening on.")
		var myPort:Int
		@Argument(help:"My private key for the Wireguard interface.")
		var myPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>

		func run() async throws {
//			let logger = Logger(label: "calendar-app-server")
//			let calendarServerService = CalendarServerService(databasePath: databasePath, configurationPath: configurationPath, myPort: myPort, myPrivateKey: myPrivateKey)
//			try await ServiceGroup(services:[calendarServerService], logger: logger).run()
		}
	}
}

extension Path:@retroactive ExpressibleByArgument {
	public init?(argument:String) {
		self.init(argument)
	}
	public var description:String {
		return self.path()
	}
}
