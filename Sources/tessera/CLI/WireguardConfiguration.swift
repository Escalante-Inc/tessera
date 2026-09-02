import Foundation
import Logging
import ArgumentParser
import RAW
import RAW_dh25519
import RAW_base64
import NIO
import bedrock
import wireguard_userspace_nio

struct WireguardConfig: Codable {
	var peers: [TesseraPeer] = []
	enum CodingKeys: String, CodingKey { case peers }
	
	init(){}

	init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		peers = try container.decodeIfPresent([TesseraPeer].self, forKey: .peers) ?? []
	}
}

internal func loadConfig(from url: URL) throws -> WireguardConfig {
	// Create empty file if it doesn't exist
	let fileManager = FileManager.default
	if !fileManager.fileExists(atPath: url.path()) {
		let emptyJSONData = "{}".data(using: .utf8)!
		fileManager.createFile(atPath: url.path(), contents: emptyJSONData)
	}
	let data = try Data(contentsOf: url)
	let decoder = JSONDecoder()
	decoder.keyDecodingStrategy = .convertFromSnakeCase
	return try decoder.decode(WireguardConfig.self, from: data)
}

internal func writeConfig(_ config: WireguardConfig, to url: URL) throws {
	let encoder = JSONEncoder()
	encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
	let data = try encoder.encode(config)
	try data.write(to: url, options: [.atomic])
}

internal func editConfig(at url: URL, _ modify: (inout WireguardConfig) throws -> Void) throws {
	var cfg = try loadConfig(from: url)
	try modify(&cfg)
	try writeConfig(cfg, to: url)
}


extension CLI {
	struct Config:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"config",
			abstract:"Subcommand for peer configuration operations",
			subcommands:[
				Add.self,
				Remove.self,
				List.self,
				Clear.self,
				Delete.self
			]
		)

		struct Add:AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				commandName:"add",
				abstract:"a subcommand for adding a peer to the configuration file."
			)
			
			@Option(help:"the path to the configuration directory, defaults to the user's home directory")
			var configurationPath:bedrock.Path = Path(FileManager.default.homeDirectoryForCurrentUser.path)
			@Option(help:"If true, will overwrite the current public key if it exists.")
			var overwrite:Bool = false
			@Option(help: "The IP address of the responder.")
			var ipAddress:String? = nil
			@Option(help: "The port number of the peer.")
			var port:Int? = nil
			@Option(help: "The internal keep-alive time of the peer (seconds).")
			var keepAlive:Int64? = nil
			@Option(help: "True if this peer is another tessera instance. Other tessera peers participate in automatic negentropy database sync; regular peers (applications) do not.")
			var tessera: Bool = false
			
			@Argument(help: "The public key of the peer.")
			var publicKey:PublicKey
			
			
			func run() async throws {
				var logger = Logger(label: "configuration")
				let configurationURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
				logger[metadataKey:"public-key"] = "\(String(describing:publicKey))"
				let keepAliveTime:TimeAmount? = keepAlive == nil ? nil : .seconds(keepAlive!)
				try editConfig(at: configurationURL) { cfg in
					if let existingIndex = cfg.peers.firstIndex(where: { $0.publicKey == publicKey }) {
						if overwrite {
							cfg.peers[existingIndex] = TesseraPeer(publicKey:publicKey, ipAddress: ipAddress, port:port, internalKeepAlive:keepAliveTime, isTessera: tessera, inboundData: nil)
							logger.info("Overwriting peer in configuration")
						} else {
							logger.info("Peer already exists in configuration")
						}
					} else {
						cfg.peers.append(TesseraPeer(publicKey:publicKey, ipAddress: ipAddress, port:port, internalKeepAlive:keepAliveTime, isTessera: tessera, inboundData: nil))
						logger.info("Adding peer to configuration")
					}
				}
			}
		}
		
		struct Remove: AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				commandName: "remove",
				abstract: "a subcommand for removing a peer from the configuration file"
			)

			@Option(help:"the path to the configuration directory, defaults to the user's home directory")
			var configurationPath:bedrock.Path = Path(FileManager.default.homeDirectoryForCurrentUser.path)
			@Argument(help: "The public key of the peer to delete.")
			var publicKey: PublicKey

			func run() async throws {
				var logger = Logger(label: "configuration")
				
				let configurationURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
				logger[metadataKey:"public-key"] = "\(String(describing:publicKey))"
				try editConfig(at: configurationURL) { cfg in
					let beforeCount = cfg.peers.count
					cfg.peers.removeAll(where: { $0.publicKey == publicKey })

					if cfg.peers.count < beforeCount {
						logger.info("Removed peer with public key: \(publicKey)")
					} else {
						logger.info("No peer found with public key: \(publicKey)")
					}
				}
			}
		}
		
		struct List: AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				commandName: "list",
				abstract: "lists the current peer configuration"
			)
			
			@Option(help:"the path to the configuration directory, defaults to the user's home directory")
			var configurationPath:bedrock.Path = Path(FileManager.default.homeDirectoryForCurrentUser.path)

			func run() async throws {
				let logger = Logger(label: "configuration")
				let configurationURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())

				let cfg = try loadConfig(from: configurationURL)
				for peer in cfg.peers {
					logger.info("Public Key:\(String(describing: peer.publicKey)), IP Address, Port:\(String(describing:peer.endpoint)), KeepAlive:\(String(describing: peer.internalKeepAlive)), Tessera:\(peer.isTessera)")
				}
			}
		}
		
		struct Clear: AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				commandName: "clear",
				abstract: "READ BEFORE USING: A subcommand for clearing the entire configuration file"
			)
			
			@Option(help:"the path to the configuration directory, defaults to the user's home directory")
			var configurationPath:bedrock.Path = Path(FileManager.default.homeDirectoryForCurrentUser.path)

			func run() async throws {
				let logger = Logger(label: "configuration")
				let configurationURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
				let emptyConfig = WireguardConfig()
				let encoder = JSONEncoder()
				encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
				let data = try encoder.encode(emptyConfig)
				try data.write(to: configurationURL, options: .atomic)
				logger.info("Successfully cleared the configuration file")
			}
		}
		
		struct Delete: AsyncParsableCommand {
			static let configuration = CommandConfiguration(
				commandName: "delete",
				abstract: "deletes the current peer configuration file"
			)
			
			@Option(help:"the path to the configuration directory, defaults to the user's home directory")
			var configurationPath:bedrock.Path = Path(FileManager.default.homeDirectoryForCurrentUser.path)

			func run() async throws {
				let logger = Logger(label: "configuration")
				let configurationURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
				try FileManager.default.removeItem(at: configurationURL)
				logger.info("Successfully cleared the configuration file")
			}
		}
	}
}
