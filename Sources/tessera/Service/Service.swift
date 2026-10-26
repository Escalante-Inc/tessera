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
import QuickLMDB

/// Returns an accurate, client-safe description of an internal error, suitable for the
/// text of a NOTICE message. The full error details are logged server-side (see the
/// caller); only a concise description of what went wrong is exposed to the client.
fileprivate func describeErrorForNotice(_ error: Error) -> String {
	switch error {
	case AccessLevelError.userDoesNotExist:
		return "The requesting user does not exist"
	case AccessLevelError.userHasNoAccessLevels:
		return "The requesting user has no configured access levels"
	case AccessLevelError.invalidReadAccess:
		return "The requesting user does not have read access for the requested kinds"
	case AccessLevelError.invalidWriteAccess:
		return "The requesting user does not have write access for this kind"
	case SignedNoteError.cantStoreEphemeralEvent:
		return "Ephemeral events cannot be stored"
	case SignedNoteError.invalidKind5Tag:
		return "Invalid deletion event: missing or malformed reference tags"
	case SignedNoteError.invalidKind5PublicKey:
		return "Deletion event references an event that was not authored by the deleting user"
	case SignedNoteError.invalidParameterizedEvent:
		return "Parameterized replaceable event is missing its d-tag"
	case SignedNoteError.invalidUserNote:
		return "Invalid user event"
	case SignedNoteError.invalidAccessLevelNote:
		return "Invalid access level event"
	case LMDBError.notFound:
		return "The requested data was not found"
	case LMDBError.keyExists:
		return "An event with this id already exists"
	case LMDBError.mapFull:
		return "The server database is full"
	case LMDBError.mapResized:
		return "The server database grew beyond its allocated size"
	default:
		return "The server could not process the request"
	}
}

/// Acts as a wrapper for storing an array of `NOSTR_message_REQ`
/// ALL requests stored in this actor are considered Active.
final actor NostrRequestsStore {
	private var nostrRequests: [PublicKey: [NOSTR_message_REQ]] = [:]

	func get(_ key: PublicKey) -> [NOSTR_message_REQ]? {
		nostrRequests[key]
	}
	func set(_ value: NOSTR_message_REQ, for key: PublicKey) {
		if nostrRequests[key] == nil {
			nostrRequests[key] = [value]
		} else {
			nostrRequests[key]?.append(value)
		}
	}
	func remove(_ key: PublicKey, subscriptionID: NOSTR_subscription_ID) {
		nostrRequests[key]?.removeAll(where: { $0.subscriptionID == subscriptionID })
		if nostrRequests[key]?.count == 0 {
			nostrRequests.removeValue(forKey: key)
		}
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
	/// How often (in seconds) the service attempts a negentropy reconciliation
	/// round with each peer flagged as a tessera. The first round runs immediately
	/// on startup; subsequent rounds run every `syncInterval` seconds.
	let syncInterval:TimeInterval
	let logLevel:Logger.Level
	
	init(databasePath:Path, configurationPath:Path, myPort:Int, myPrivateKey:MemoryGuarded<RAW_dh25519.PrivateKey>, syncInterval:TimeInterval = 30, logLevel:Logger.Level = .debug) {
		self.databasePath = databasePath
		self.configurationPath = configurationPath
		self.myPort = myPort
		self.myPrivateKey = myPrivateKey
		self.syncInterval = syncInterval
		self.logLevel = logLevel
	}
	
	func run() async throws {
		var tempLogger = Logger(label: "tessera-server-service")
		tempLogger.logLevel = self.logLevel
		let cliLogger = tempLogger
		
		let nostrRequests = NostrRequestsStore()
		let tesseraDB = try TesseraDB.openTessera(base: databasePath, memoryMapSize: size_t(databasePath.getFileSize() + 512 * 1024 * 1024 * 1024), logLevel: self.logLevel)
		
		// Load the Wireguard peers from the json encoded configuration file.
		let jsonURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
		let cfg = try loadConfig(from: jsonURL)
		
		try await cancelWhenGracefulShutdown {
			_ = try await withThrowingTaskGroup(body: { foo in
				
				// Create all of the Wireguard peers configured for this device.
				// These peers include other tessera devices and applications (users).
				// Then start the primary Wireguard interface.
				// There is one Wireguard interface for all connections (peers). (might change)
				//
				// Each peer may be another tessera (isTessera) or an application/user.
				// Tessera peers participate in negentropy synchronization; each gets a
				// dedicated sync FIFO that the per-peer task feeds negentropy frames into.
				var peerInfos:[(peer: TesseraPeer, syncFIFO: FIFO<ByteBuffer, Swift.Error>?)] = []
				for peer in cfg.peers {
					let peerInfo = TesseraPeer(publicKey: peer.publicKey, sharedKey: peer.sharedKey, endpoint: peer.endpoint, internalKeepAlive: peer.internalKeepAlive, isTessera: peer.isTessera, inboundData: try FIFO<ByteBuffer, Swift.Error>())
					peerInfos.append((peerInfo, peer.isTessera ? try FIFO<ByteBuffer, Swift.Error>() : nil))
				}
				let myInterface = try WGInterface<KCPChannels>(staticPrivateKey: self.myPrivateKey, mtu:1400, initialConfiguration: peerInfos.map { $0.peer }, logLevel:self.logLevel, listeningPort: self.myPort)
				
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
				// Negentropy frames ("NEGT" magic) from a peer flagged as a tessera are
				// routed into that peer's dedicated sync FIFO for reconciliation.
				let syncGate = SyncGate()
				let myPublicKey = PublicKey(privateKey: self.myPrivateKey)
				for (peerInfo, syncFIFO) in peerInfos {
					// Start the negentropy sync loop for peers that are other tesserae.
					// Peers that are not flagged as tesserae never sync (the share
					// subscription fan-out remains their only data path).
					if peerInfo.isTessera, let syncFIFO {
						let negentropyManager = NegentropySyncManager(
							tesseraDB: tesseraDB,
							channel: channel,
							myPublicKey: myPublicKey,
							peer: peerInfo,
							syncFIFO: syncFIFO,
							logLevel: cliLogger.logLevel,
							interval: self.syncInterval
						)
						foo.addTask {
							do {
								try await negentropyManager.runForever(gate: syncGate)
							} catch {
								cliLogger.error("Negentropy sync loop exited for peer \(String(describing: peerInfo.publicKey)): \(String(describing: error))")
								throw error
							}
						}
					}
					foo.addTask {
						var buffer = ByteBufferAllocator().buffer(capacity: 1024)
						
						func writeToInterface(publicKey: PublicKey, data: any RAW_encodable) throws {
							var messageLength = 0; data.RAW_encode(count: &messageLength)
							if buffer.capacity < messageLength {
								buffer.reserveCapacity(messageLength + 64)
							}
							buffer.withUnsafeMutableWritableBytes { ptr in
								guard let base = ptr.baseAddress else { return }
								let ptr = base.assumingMemoryBound(to: UInt8.self)
								_ = data.RAW_encode(dest: ptr)
							}
							buffer.moveWriterIndex(forwardBy: messageLength)
							try WGInterface<KCPChannels>.write(channel: channel, publicKey: publicKey, data: buffer)
							buffer.clear(minimumCapacity: 1024)
						}
						let iterator = peerInfo.inboundData?.makeAsyncConsumer()
						while !Task.isCancelled {
							do {
								if let incomingSignal = try await iterator?.next(whenTaskCancelled: .finish(.success(()))) {
									
									// Route negentropy sync frames to the sync manager.
									// Non-tessera peers are not expected to send these; they
									// simply fail NOSTR decoding and are ignored below.
									if let syncFIFO, isNegentropyFrame(incomingSignal) {
										syncFIFO.yield(incomingSignal)
										continue
									}
									
									// Try to decode the incoming Wireguard data.
									// Try deciding as every different possible Nostr message type.
									//
									// SeeAlso: [https://github.com/bwyma1/nostr-kit-swift/blob/main/Sources/nostr-kit-swift/Message/NOSTR_message.swift]
									cliLogger.debug("Received incoming data. Checking for NOSTR messages.")
									// Decode the incoming Wireguard data as a single NOSTR message.
									var message:NOSTR_message<UnsignedEvent<ByteBuffer>>?
									incomingSignal.withUnsafeReadableBytes { ptr in
										message = NOSTR_message<UnsignedEvent<ByteBuffer>>.decode(ptr)
									}
									switch message {
										case .REQ(let request):
											cliLogger.debug("Processing REQ Message")
											
											await nostrRequests.set(request, for: peerInfo.publicKey)
											
											let signedEvents: [TesseraSignedEvent]
											if request.fetchHistory.bool {
												signedEvents = try tesseraDB.queryEventsByDumbFilter(filters: request.filters, user: request.user)
											} else {
												signedEvents = try tesseraDB.queryEventsBySmartFilter(filters: request.filters, user: request.user)
											}
											
											cliLogger.debug("Found \(signedEvents.count) events from REQ Message")
											for event in signedEvents {
												let outgoingEventMessage = NOSTR_message_EVENT(subscriptionID: request.subscriptionID, event: event)
												try writeToInterface(publicKey: peerInfo.publicKey, data: outgoingEventMessage)
											}
					
											let eoseMsg = NOSTR_message_EOSE(subscriptionID: request.subscriptionID)
											try writeToInterface(publicKey: peerInfo.publicKey, data: eoseMsg)
											
										case .EVENT(let incomingEventMessage):
											cliLogger.debug("Processing EVENT Message")
											let event = incomingEventMessage.event
											cliLogger.debug("Event signature valid: \(event.isValidSignature()) ; config:\(event.unsignedEvent.application) kind:\(event.unsignedEvent.kind.RAW_native()) id:\(String(describing: event.unsignedEvent.id))")
											guard event.isValidSignature() else {
												break
											}
											
											do {
												try tesseraDB.scribeNewEvent(signedEvent: event, logLevel: cliLogger.logLevel)
												cliLogger.debug("Scribe committed OK")
											} catch AccessLevelError.invalidWriteAccess {
												try writeToInterface(publicKey: peerInfo.publicKey, data: NOSTR_message_NOTICE(noticeText: "User lacks write access credentials"))
												cliLogger.debug("Scribe FAILED invalidWriteAccess")
											} catch LMDBError.mapFull {
												cliLogger.critical("RELAY STORAGE EXHAUSTED (mapFull): the LMDB database is full; new events cannot be stored. Free disk space / grow the LMDB mmap to resume writes. Peer: \(String(describing: peerInfo.publicKey))")
												throw LMDBError.mapFull
											} catch LMDBError.mapResized {
												cliLogger.critical("RELAY STORAGE EXHAUSTED (mapResized): the LMDB database grew beyond its allocated size; new events cannot be stored. Free disk space / grow the LMDB mmap to resume writes. Peer: \(String(describing: peerInfo.publicKey))")
												throw LMDBError.mapResized
											} catch {
												cliLogger.error("Scribe FAILED: \(error)")
												throw error
											}
									
											if event.unsignedEvent.kind.RAW_native() == 5 {
												cliLogger.debug("Deletion event, fanning out to matching subscriptions")

												// NIP-09: a deletion event targets the events references by its `e` tags.
												// Peers whose active subscriptions match those deleted events must be told
												// to purge them locally, just as they were told about the events themselves.
												// (The referenced events remain in the store — removal is applied at query
												// time — so they can be loaded to evaluate subscription filters against.)
												var referencedEvents: [TesseraSignedEvent] = []
												for tag in event.unsignedEvent.tags.array {
													guard let eventRefTag = tag.unwrap(as: EventRefTag.self) else { continue }
													// Scribe validated these exist, but skip defensively if it was force-removed.
													if let referenced = try? tesseraDB.queryEventID(eventRefTag.value) {
														referencedEvents.append(referenced)
													}
												}

												var publisherCovered = false
												let allRequests = await nostrRequests.all()
												for (peerKey, requests) in allRequests {
													for request in requests {
														cliLogger.debug("Checking if request filter matches deletion message")
														// Deliver if the subscription matches the deletion event itself
														// (e.g. `kinds: [5]`) OR any of the events it references (NIP-09),
														// so a subscriber of the deleted event's kind/author also hears about it.
														let matches = eventMatchesFilters(event, filters: request.filters, logLevel: cliLogger.logLevel)
															|| referencedEvents.contains { eventMatchesFilters($0, filters: request.filters, logLevel: cliLogger.logLevel) }
														if matches {
															cliLogger.debug("Request filter matched deletion, sending newly written event")
															let outgoingEventMessage = NOSTR_message_EVENT(subscriptionID: request.subscriptionID, event: event)
															try writeToInterface(publicKey: peerKey, data: outgoingEventMessage)
															if peerKey == peerInfo.publicKey {
																publisherCovered = true
															}
														}
													}
												}
												// Always acknowledge the deletion to the publisher (purges its local
												// model) even when it holds no matching active subscription.
												if !publisherCovered {
													try writeToInterface(publicKey: peerInfo.publicKey, data: NOSTR_message_EVENT(subscriptionID: "", event: event))
												}
											} else {
												let allRequests = await nostrRequests.all()
												for (peerKey, requests) in allRequests {
													for request in requests {
														cliLogger.debug("Checking if request filter matches message")
														// If the event matches any current filters, then send it over.
														// The event is sent as a nostr message with the same subscription id as the filter request.
														if(eventMatchesFilters(event, filters: request.filters, logLevel: cliLogger.logLevel)) {
															cliLogger.debug("Request filter matched, sending newly written event")
															let outgoingEventMessage = NOSTR_message_EVENT(subscriptionID: request.subscriptionID, event: event)
															try writeToInterface(publicKey: peerKey, data: outgoingEventMessage)
														}
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
							catch let error {
								cliLogger.error("Failed to process incoming data", metadata: ["peer": "\(String(describing: peerInfo.publicKey))", "error": "\(String(describing: error))"])
								do {
									try writeToInterface(publicKey: peerInfo.publicKey, data: NOSTR_message_NOTICE(noticeText: describeErrorForNotice(error)))
								} catch let error {
									cliLogger.error("Failed to send NOTICE", metadata: ["peer": "\(String(describing: peerInfo.publicKey))", "error": "\(String(describing: error))"])
								}
							}
						}
					}
				}
				try await foo.waitForAll()
			})
		}
	}
}

