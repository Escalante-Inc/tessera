import Foundation
import Logging
import NIO
import ServiceLifecycle
import wireguard_userspace_nio
import nostr_kit_swift
import tessera_core
import bedrock_fifo
import bedrock
import RAW
import RAW_dh25519

/// Acts as a wrapper for storing an array of `NOSTR_message_REQ`
/// ALL requests stored in this actor are considered Active.
final actor NostrRequestsStore {
	private var nostrRequests: [PublicKey: [NOSTR_message_REQ]] = [:]

	func get(_ key: PublicKey) -> [NOSTR_message_REQ]? {
		nostrRequests[key]
	}
	func set(_ value: NOSTR_message_REQ, for key: PublicKey) {
		if nostrRequests[key] != nil {
			nostrRequests[key] = [value]
		} else {
			nostrRequests[key]?.append(value)
		}
	}
	func remove(_ key: PublicKey, subscriptionID: NOSTR_subscription_ID) {
		nostrRequests[key]?.removeAll(where: { $0.subscriptionID == subscriptionID })
	}
	func removeAll() {
		nostrRequests.removeAll()
	}
	func all() -> [PublicKey: [NOSTR_message_REQ]] {
		nostrRequests
	}
	func contains(_ key: PublicKey) -> Bool {
		nostrRequests[key] != nil
	}
}

/// The primary running service for Tessera.
/// The service should only go down under critical errors or restarting for updates.
/// The servive runs a Wireguard server on localhost:myPort to transfer/receive data from
/// both users (applications or admins) and other tesserae.
///
/// - Parameters
///   - databasePath: The file path to the folder where the TesseraDB (.mdb, .mdb-lock) are stored.
///   - myPort: The port on this device where the Wireguard server runs.
///   - myPrivateKey: The private key for the Wireguard server.
final class TesseraService: Service {
	let databasePath:bedrock.Path
	let configurationPath:Path
	let myPort:Int
	let myPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>
	
	init(databasePath:Path, configurationPath:Path, myPort:Int, myPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>) {
		self.databasePath = databasePath
		self.configurationPath = configurationPath
		self.myPort = myPort
		self.myPrivateKey = myPrivateKey
	}
	
	func run() async throws {
		var tempLogger = Logger(label: "tessera-server-service")
		tempLogger.logLevel = .debug
		let cliLogger = tempLogger
		
		let nostrRequests = NostrRequestsStore()
		let tesseraDB = try TesseraDB(base: databasePath, memoryMapSize: size_t(databasePath.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: .debug)
		
		// Load the Wireguard peers from the json encoded configuration file.
		let jsonURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
		let cfg = try loadConfig(from: jsonURL)
		
		try await cancelWhenGracefulShutdown {
			_ = try await withThrowingTaskGroup(body: { foo in
				
				// Create all of the Wireguard peers configured for this device.
				// These peers include other tessera devices and applications (users).
				// Then start the primary Wireguard interface.
				// There is one Wireguard interface for all connections (peers). (might change)
				// (maybe need to have different interface for tessera vs applications)
				var peerInfos:[PeerInfo] = []
				for peer in cfg.peers {
					peerInfos.append(PeerInfo(publicKey:peer.publicKey, endpoint: peer.endpoint, internalKeepAlive: peer.internalKeepAlive, inboundData: FIFO<ByteBuffer, Swift.Error>()))
				}
				let myInterface = try WGInterface<KCPChannels>(staticPrivateKey: self.myPrivateKey, mtu:1400, initialConfiguration:peerInfos, logLevel:.info, listeningPort: self.myPort)
				
				foo.addTask {
					try await myInterface.run()
				}
				
				cliLogger.info("WireGuard interface started. Waiting for channel initialization...")
				try await myInterface.waitForChannelInit()
				let channel = try await myInterface.getChannel()
				
				// Run a task for each peer connected to the wireguard interface.
				// Each task handles the following tessera features.
				// - Receiving signed events from other tessera or applications (users).
				// - Receiving requests from applications (users).
				// - Receiving request closures from applications (users).
				// - Sending signed events to tessera via sync or applications (users) via requests.
				for peerInfo in peerInfos {
					foo.addTask {
						do {
							var buffer = ByteBufferAllocator().buffer(capacity: 1024)
							let iterator = peerInfo.inboundData?.makeAsyncConsumer()
							while !Task.isCancelled {
								if let incomingSignal = try await iterator?.next(whenTaskCancelled: .finish) {
									
									// Try to decode the incoming Wireguard data.
									// Try deciding as every different possible Nostr message type.
									//
									// SeeAlso: [https://github.com/bwyma1/nostr-kit-swift/blob/main/Sources/nostr-kit-swift/Message/NOSTR_message.swift]
									cliLogger.debug("Received incoming data. Checking for NOSTR messages.")
									var message:NOSTR_message<UnsignedEvent<ByteBuffer>>?
									incomingSignal.withUnsafeReadableBytes { ptr in
										// Try EVENT Message
										do {
											guard let event = NOSTR_message_EVENT<UnsignedEvent<ByteBuffer>>(RAW_decode: ptr.baseAddress!, count: ptr.count) else {
												throw NOSTR_message_error.badDecode
											}
											message = .EVENT(event)
										} catch { }
										// Try REQ Message
										do {
											guard let request = NOSTR_message_REQ(RAW_decode: ptr.baseAddress!, count: ptr.count) else {
												throw NOSTR_message_error.badDecode
											}
											message = .REQ(request)
										} catch { }
										// Try CLOSE Message
										do {
											guard let close = NOSTR_message_CLOSE(RAW_decode: ptr.baseAddress!, count: ptr.count) else {
												throw NOSTR_message_error.badDecode
											}
											message = .CLOSE(close)
										} catch { }
										
									}
									switch message {
										case .REQ(let request):
											cliLogger.debug("Processing REQ Message")
											
											await nostrRequests.set(request, for: peerInfo.publicKey)
											
											let signedEvents:[TesseraSignedEvent] = try tesseraDB.queryEventsBySmartFilter(filters: request.filters)
											
											cliLogger.debug("Found \(signedEvents.count) events from REQ Message")
											for event in signedEvents {
												let outgoingEventMessage = NOSTR_message_EVENT(subscriptionID: request.subscriptionID, event: event)
												var messageLength = 0; outgoingEventMessage.RAW_encode(count: &messageLength)
												buffer.withUnsafeMutableWritableBytes { ptr in
													guard let base = ptr.baseAddress else { return }
													let ptr = base.assumingMemoryBound(to: UInt8.self)
													_ = outgoingEventMessage.RAW_encode(dest: ptr)
												}
												buffer.moveWriterIndex(forwardBy: messageLength)
												try WGInterface<KCPChannels>.write(channel: channel, publicKey: peerInfo.publicKey, data: buffer)
												buffer.clear(minimumCapacity: 1024)
											}
											
										case .EVENT(let incomingEventMessage):
											cliLogger.debug("Processing EVENT Message")
											let event = incomingEventMessage.event
											guard event.isValidSignature() else {
												break
											}
											try tesseraDB.scribeNewEvent(signedEvent: event, logLevel: cliLogger.logLevel)
											
											let allRequests = await nostrRequests.all()
											for (key, requests) in allRequests {
												for request in requests {
													// If the event matches any current filters, then send it over.
													// The event is sent as a nostr message with the same subscription id as the filter request.
													if(eventMatchesFilters(event, filters: request.filters, logLevel: cliLogger.logLevel)) {
														let outgoingEventMessage = NOSTR_message_EVENT(subscriptionID: request.subscriptionID, event: event)
														var messageLength = 0; outgoingEventMessage.RAW_encode(count: &messageLength)
														buffer.withUnsafeMutableWritableBytes { ptr in
															guard let base = ptr.baseAddress else { return }
															let ptr = base.assumingMemoryBound(to: UInt8.self)
															_ = outgoingEventMessage.RAW_encode(dest: ptr)
														}
														buffer.moveWriterIndex(forwardBy: messageLength)
														try WGInterface<KCPChannels>.write(channel: channel, publicKey: key, data: buffer)
														buffer.clear(minimumCapacity: 1024)
													}
												}
											}
										case .CLOSE(let closeMessage):
											cliLogger.debug("Processing CLOSE Message")
											await nostrRequests.remove(peerInfo.publicKey, subscriptionID: closeMessage.subscriptionID)
										case nil:
											cliLogger.debug("Incoming data didn't match any NOSTR Message type. Ignoring.")
											break
										default:
											break
											// need to add other messages
									}
								}
							}
							
						} catch let error{
							print(error)
						}
							
					}
				}
				
				try await foo.waitForAll()
			})
		}
	}
}

