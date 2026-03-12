import Foundation
import tessera_core
import RAW
import RAW_dh25519
import RAW_base64
import RAW_ed25519
import NIO
import Logging
import ArgumentParser
import ServiceLifecycle
import openpgp_kit_swift
import nostr_kit_swift
import bedrock

@main
struct CLI:AsyncParsableCommand {
	static func defaultDBBasePath() -> Path {
		return Path(FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("tessera_lmdb").path)
	}
	
	static let configuration = CommandConfiguration(
		commandName:"tessera-service",
		abstract:"a server side program for the calendar app",
		subcommands:[
				Run.self,
				GenerateKeys.self,
				GenerateEd25519Keys.self,
				CreateNewAccessLevel.self,
				CreateUser.self,
				Config.self
			]
		)
	
	struct GenerateKeys:ParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"Generate a new WireGuard key pair."
		)
		func run() throws {
			let pk = try MemoryGuarded<PrivateKey>.new()
			let (publicKey, privateKey) = (PublicKey(privateKey:pk), pk)
			let publicKeyBase64 = String(RAW_base64.encode(publicKey))
			let privateKeyBase64 = String(RAW_base64.encode(privateKey))
			print("Public Key: \(publicKeyBase64)")
			print("Private Key: \(privateKeyBase64)")
		}
	}
	
	struct GenerateEd25519Keys:ParsableCommand {
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
	
	struct CreateNewAccessLevel:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"Generate a new Tessera access level. Requires master level access yubikey to run."
		)
		
		@Option(help:"the path to the database directory, defaults to the user's home directory")
		var databasePath:bedrock.Path = CLI.defaultDBBasePath()
		
		@Argument(help:"The numerical value of the access level (UInt16).")
		var index: UInt8
		
		@Argument(help:"The name of the access level.")
		var name: String
		
		func run() async throws {
			let tesseraDB = try TesseraDB(base: databasePath, memoryMapSize: size_t(databasePath.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .debug)
			let openPGPConnection = OpenPGPConnection(logLevel: .debug)
			try await openPGPConnection.connectToYubikey()
			try await openPGPConnection.startOpenPGP()
			let publicKey = try await openPGPConnection.getPublicKeys().first!
			
			let unsignedEvent = try UnsignedEvent(publicKey: publicKey, tags: [EventTag(accessLevel: index), EventTag(accessLevel: name)], application: 0, kind: 1, content: ByteBuffer())
			try await openPGPConnection.openVerifyAccess(pwType: .user, password: "123456".data(using: .utf8)!)
			let sig = try await openPGPConnection.computeDitigalSignature(hashedData: unsignedEvent.id)
			try await openPGPConnection.closeVerifyAccess(pwType: .user)
			try sig.withUnsafeBytes { ptr in
				let nostrSig = NOSTR_sig(RAW_staticbuff: ptr.baseAddress!)
				let signedEvent = NOSTR_event_signed(unsignedEvent: unsignedEvent, sig: nostrSig)
				try tesseraDB.scribeNewEvent(signedEvent: signedEvent, logLevel: .debug)
			}
		}
	}
	
	struct CreateUser:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			abstract:"Creates a new user for the tesserae. Requires a yubikey to be plugged into the device."
		)
		
		@Option(help:"the path to the database directory, defaults to the user's home directory")
		var databasePath:bedrock.Path = CLI.defaultDBBasePath()
		
		@Option(help:"The users read permissions.")
		var readPermissions: [String] = []
		
		@Option(help:"The users write permissions.")
		var writePermissions: [String] = []
		
		@Argument(help:"The users name.")
		var userName:String

		func run() async throws {
			let tesseraDB = try TesseraDB(base: databasePath, memoryMapSize: size_t(databasePath.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .debug)
			var filters = readPermissions.map { Filter(kinds: [NOSTR_kind(RAW_native: 1)], tags: [EventTag(accessLevel: $0)]) }
			var events = try tesseraDB.queryEventsBySmartFilter(filters: filters)
			let readPermNumbers:[UInt8] = events.map({ String($0.unsignedEvent.tags.array.first{ $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "perm")}?.NOSTR_tag_values.array.first! as! NOSTR_tag_generic_value).utf8.first! })
			
			filters = writePermissions.map { Filter(kinds: [NOSTR_kind(RAW_native: 1)], tags: [EventTag(accessLevel: $0)]) }
			events = try tesseraDB.queryEventsBySmartFilter(filters: filters)
			let writePermNumbers:[UInt8] = events.map({ String($0.unsignedEvent.tags.array.first{ $0.NOSTR_tag_index_field == NOSTR_tag_name(string: "perm")}?.NOSTR_tag_values.array.first! as! NOSTR_tag_generic_value).utf8.first! })
			
			let openPGPConnection = OpenPGPConnection(logLevel: .debug)
			try await openPGPConnection.connectToYubikey()
			try await openPGPConnection.startOpenPGP()
			let publicKey = try await openPGPConnection.getPublicKeys().first!
			
			let userEvent = try UnsignedEvent(publicKey: publicKey,
											  tags: [EventTag(tagName: "userName", tagValues: [userName]),
													 EventTag(tagName: "readAccessLevels", tagValues: [UserAccessLevel(accessLevels: readPermNumbers)]),
													 EventTag(tagName: "writeAccessLevels", tagValues: [UserAccessLevel(accessLevels: writePermNumbers)])],
											  application: 0,
											  kind: 0,
											  content: ByteBuffer())
			try await openPGPConnection.openVerifyAccess(pwType: .user, password: "123456".data(using: .utf8)!)
			let sig = try await openPGPConnection.computeDitigalSignature(hashedData: userEvent.id)
			try await openPGPConnection.closeVerifyAccess(pwType: .user)
			try sig.withUnsafeBytes { ptr in
				let nostrSig = NOSTR_sig(RAW_staticbuff: ptr.baseAddress!)
				let signedEvent = NOSTR_event_signed(unsignedEvent: userEvent, sig: nostrSig)
				try tesseraDB.scribeNewUser(signedEvent: signedEvent, logLevel: .debug)
			}
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
			let logger = Logger(label: "tessera-server")
			let tesseraService = TesseraService(databasePath: databasePath, configurationPath: configurationPath, myPort: myPort, myPrivateKey: myPrivateKey)
			try await ServiceGroup(services:[tesseraService], logger: logger).run()
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
