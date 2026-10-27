import Foundation
import Logging
import Synchronization
import tessera_core
import bedrock
import RAW
import RAW_base64
import RAW_dh25519
import RAW_ed25519
import nostr_kit_swift
import NIOCore
import QuickLMDB
#if canImport(WebUI)
import WebUI
import WebUIDesignSystem
import WebUIServer

// MARK: - Admin auth

/// Thrown when a credential string is not a base64 32-byte key.
private struct InvalidAdminKey:Swift.Error {}

/// Session-backed login for the admin dashboard, enabled only when an
/// `--admin-key` is configured. The login page presents a username and the
/// base64 admin secret key; the server derives the key's public half and
/// constant-time-compares it against the configured admin key's public key,
/// then issues an HttpOnly session cookie (12 h). Read-only mode (no admin
/// key) has nothing to protect and skips auth entirely.
///
/// The username is recorded with the session (shown in the header) but is not
/// a credential — the secret key is the only thing verified.
final class AdminAuth: Sendable {
	/// the cookie the session token rides in.
	static let cookieName = "tessera_admin_session"
	/// how long a login session lives.
	static let sessionLifetime:TimeInterval = 12 * 60 * 60

	struct Session:Sendable {
		let username:String
	}

	private struct Entry:Sendable {
		let username:String
		let expires:Foundation.Date
	}

	private let expectedPublicKey:String
	private let entries = Mutex<[String: Entry]>([:])
	private let logger:Logger

	/// - parameter adminKey: the base64 `RAW_dh25519.PrivateKey` the server was
	///   started with; its derived public half is the only accepted credential.
	init(adminKey:String, logLevel:Logger.Level) throws {
		let secretData = try AdminAuth.decodeSecret(adminKey)
		let (publicKey, _) = try RAW_ed25519.generateKeys(secretKey: secretData)
		self.expectedPublicKey = String(RAW_base64.encode(publicKey))
		var logger = Logger(label: "tessera-admin-auth")
		logger.logLevel = logLevel
		self.logger = logger
	}

	/// Decodes a base64 32-byte `RAW_dh25519.PrivateKey`.
	static func decodeSecret(_ base64:String) throws -> MemoryGuarded<RAW_dh25519.PrivateKey> {
		guard let bytes = try? RAW_base64.decode(base64), bytes.count == 32 else {
			throw InvalidAdminKey()
		}
		return try bytes.withUnsafeBytes { ptr -> MemoryGuarded<RAW_dh25519.PrivateKey> in
			guard let guarded = MemoryGuarded<RAW_dh25519.PrivateKey>(RAW_decode: ptr) else {
				throw InvalidAdminKey()
			}
			return guarded
		}
	}

	/// Verifies the presented credentials. Returns the session token to set as
	/// the cookie value, or `nil` when the secret key does not match the
	/// configured admin key.
	func login(username:String, secretKey:String) -> String? {
		guard let secretData = try? AdminAuth.decodeSecret(secretKey) else { return nil }
		let derived:PublicKey
		do {
			let (publicKey, _) = try RAW_ed25519.generateKeys(secretKey: secretData)
			derived = publicKey
		} catch {
			logger.warning("login key derivation failed: \(error)")
			return nil
		}
		let candidate = String(RAW_base64.encode(derived))
		guard constantTimeEquals(candidate.utf8, expectedPublicKey.utf8) else { return nil }

		let tokenBytes = SecureRandom.bytes(32) ?? Array((0..<32).map { _ in UInt8.random(in: 0...255) })
		let token = tokenBytes.map { String(format: "%02x", $0) }.joined()
		let expiry = Foundation.Date().addingTimeInterval(AdminAuth.sessionLifetime)
		entries.withLock { $0[token] = Entry(username: username, expires: expiry) }
		logger.info("admin login: username \(username)")
		return token
	}

	/// The live session for a request's cookies, with expired entries pruned.
	func session(for cookies:[String: String]) -> Session? {
		guard let token = cookies[AdminAuth.cookieName] else { return nil }
		return entries.withLock { dict -> Session? in
			guard let entry = dict[token] else { return nil }
			if entry.expires < Date() {
				dict.removeValue(forKey: token)
				return nil
			}
			return Session(username: entry.username)
		}
	}

	/// Ends a session (logout).
	func logout(token:String) {
		entries.withLock { $0.removeValue(forKey: token) }
	}
}

// MARK: - Admin WebUI

/// The sections of the admin dashboard. The active section is server-side
/// state; navigation re-renders the `#section` fragment over the WebSocket.
enum AdminSection: String, CaseIterable, Sendable {
	case overview
	case users
	case peers
	case transactions
	case accessLevels

	var label:String {
		switch self {
			case .overview: return "Overview"
			case .users: return "Users"
			case .peers: return "Peers"
			case .transactions: return "Transactions"
			case .accessLevels: return "Access Levels"
		}
	}
}

/// A removal awaiting confirmation in the dashboard.
enum PendingConfirm:Sendable {
	case removeUser(key:String, name:String)
	case removePeer(key:String)
}

/// Hosts the tessera admin dashboard over HTTP + WebSocket using no-webui's
/// `WebUIServer` (no-webui 2.x).
///
/// The server holds an open handle to the relay's LMDB database and the peer
/// configuration directory. Every section render queries live data; a poller
/// broadcasts the active section to connected clients on an interval.
///
/// The page is rendered per request inside the server-owned `RenderContext`
/// (see `WebUIServer`), so the delegated controls register their handlers into
/// the event router under this connection's render session. Fragment updates
/// produced by handlers are built *outside* any render context: the controls
/// they carry re-emit the same stable `data-component-id` attributes without
/// re-registering, which is exactly the framework's contract for stable ids.
final class AdminWebUIServer: Sendable {
	let db:TesseraDB
	let databasePath:Path
	let configurationPath:Path
	let activityWindowDays:Int
	let host:String
	let port:Int
	let router:EventRouter
	let currentSection:Mutex<AdminSection>
	/// base64-encoded `RAW_dh25519.PrivateKey` of an admin identity. When set,
	/// the dashboard can add/remove users (signing kind-0 user events with this
	/// key). `nil` keeps the Users section read-only.
	let adminKey:String?
	/// session-backed login. `nil` in read-only mode (no admin key): the
	/// dashboard is then public and there is nothing to protect.
	let auth:AdminAuth?
	/// whether the "add user" form is open in the Users section.
	let addingUser:Mutex<Bool>
	/// whether the "add peer" form is open in the Peers section.
	let addingPeer:Mutex<Bool>
	/// whether the "add access level" form is open in the Access Levels section.
	let addingAccess:Mutex<Bool>
	/// a just-created user awaiting secret handoff: (name, base64 secret key).
	/// Rendered once with the section, then cleared on the next action.
	let createdUser:Mutex<(name:String, secret:String)?>
	/// the name of a just-created user whose public key was supplied (no
	/// secret to show); cleared on next interaction.
	let createdByoUser:Mutex<String?>
	/// a pending removal awaiting user confirmation; rendered as an inline
	/// confirm panel (which survives live pushes) until confirmed or cancelled.
	let pendingConfirm:Mutex<PendingConfirm?>
	/// the last failed mutation, rendered as an error banner until the next
	/// successful action or navigation.
	let lastError:Mutex<String?>
	let logger:Logger
	/// how often the dashboard re-renders the visible section and broadcasts it to
	/// connected clients; `0` disables live updates entirely.
	let pollInterval:TimeInterval

	init(db:TesseraDB, databasePath:Path, configurationPath:Path, activityWindowDays:Int, host:String, port:Int, pollInterval:TimeInterval = 15, adminKey:String? = nil, logLevel:Logger.Level) throws {
		self.db = db
		self.databasePath = databasePath
		self.configurationPath = configurationPath
		self.activityWindowDays = activityWindowDays
		self.host = host
		self.port = port
		self.pollInterval = pollInterval
		self.adminKey = adminKey
		if let adminKey {
			self.auth = try AdminAuth(adminKey: adminKey, logLevel: logLevel)
		} else {
			self.auth = nil
		}
		self.router = EventRouter()
		self.currentSection = Mutex<AdminSection>(.overview)
		self.addingUser = Mutex<Bool>(false)
		self.addingPeer = Mutex<Bool>(false)
		self.addingAccess = Mutex<Bool>(false)
		self.createdUser = Mutex<(name:String, secret:String)?>(nil)
		self.createdByoUser = Mutex<String?>(nil)
		self.pendingConfirm = Mutex<PendingConfirm?>(nil)
		self.lastError = Mutex<String?>(nil)
		var logger = Logger(label: "tessera-admin-webui")
		logger.logLevel = logLevel
		self.logger = logger
	}

	// MARK: data loading (sync, boundary-dialect reads)

	private func loadStats() -> AdminEventStats? {
		guard var stats = try? db.adminEventStats() else { return nil }
		if let attributes = try? FileManager.default.attributesOfItem(atPath: databasePath.appendingPathComponent("tessera.mdb").path()), let size = attributes[.size] as? Int64 {
			stats = stats.withDatabaseFileSize(size)
		}
		return stats
	}

	private func loadUsers() -> [AdminUserInfo] {
		return (try? db.adminListUsers()) ?? []
	}

	private func loadPeers() -> (tesserae:Int, applications:Int, rows:[(key:String, isTessera:Bool, endpoint:String, keepAlive:String)]) {
		let jsonURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
		guard let cfg = try? loadConfig(from: jsonURL) else { return (0, 0, []) }
		let rows = cfg.peers.map { peer in
			return (
				key: String(RAW_base64.encode(peer.publicKey)),
				isTessera: peer.isTessera,
				endpoint: peer.endpoint.map { String(describing: $0) } ?? "-",
				keepAlive: peer.internalKeepAlive.map { "\($0.nanoseconds / 1_000_000_000)s" } ?? "-"
			)
		}
		return (cfg.peers.filter { $0.isTessera }.count, cfg.peers.filter { !$0.isTessera }.count, rows)
	}

	private func loadTransactions(limit:Int) -> [PeerTransactionRecord] {
		let log = PeerTransactionLog(base: databasePath, logLevel: logger.logLevel)
		return log.read(limit: limit)
	}

	private func loadAccessLevels() -> [AdminAccessLevelInfo] {
		return (try? db.adminListAccessLevels()) ?? []
	}

	private static func shortKey(_ key:String, length:Int = 16) -> String {
		return key.count <= length ? key : key.prefix(length) + "…"
	}

	private static func formatBytes(_ bytes:Int64) -> String {
		let formatter = ByteCountFormatter()
		formatter.countStyle = .binary
		return formatter.string(fromByteCount: bytes)
	}

	private static func formatDate(_ date:Foundation.Date?) -> String {
		guard let date else { return "-" }
		return date.formatted(date: .abbreviated, time: .shortened)
	}

	private static func userStatus(lastActivity:Foundation.Date?, windowDays:Int) -> (label:String, tone:Tone) {
		guard let lastActivity else { return ("never active", .neutral) }
		let window = TimeInterval(windowDays) * 86_400
		return (Date().timeIntervalSince(lastActivity) <= window) ? ("active", .success) : ("inactive", .warning)
	}

	// MARK: rendering

	/// The page-scoped layout styles (the design system is linked by
	/// `WebUIDocument` through the content-addressed sheet the server serves).
	private static let layoutStyles = [
		".admin { max-width: 1100px; margin: 0 auto; padding: var(--space-6); }",
		".admin__header { padding-bottom: var(--space-4); }",
		".admin__header-row { display: flex; align-items: baseline; justify-content: space-between; gap: var(--space-3); }",
		".admin__session { display: inline-flex; align-items: baseline; gap: var(--space-3); font-size: 0.85rem; color: var(--color-text-muted); }",
		".admin__session a { color: var(--color-text-muted); }",
		".admin__session a:hover { color: var(--color-text); }",
		".admin__header p { color: var(--color-text-muted); margin: var(--space-1) 0 0 0; }",
		".admin__nav { display: flex; gap: var(--space-2); padding-bottom: var(--space-4); flex-wrap: wrap; }",
		".admin__section { display: flex; flex-direction: column; gap: var(--space-4); }",
		".admin__statgrid { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: var(--space-4); }",
		".admin__keycell { display: inline-flex; align-items: center; gap: var(--space-2); }",
		".copy-key { display: inline-flex; align-items: center; cursor: pointer; color: var(--color-text-muted); border-radius: var(--radius-sm, 4px); }",
		".copy-key:hover, .copy-key:focus-visible { color: var(--color-text); }",
		".copy-key:focus-visible { outline: 2px solid var(--color-primary); outline-offset: 2px; }",
		".copy-key.copied { color: var(--color-success); }",
		".admin__hidden { display: none; }",
		".admin__error { padding: var(--space-3) var(--space-4); border: 1px solid var(--color-danger, #b3261e); border-radius: var(--radius-md, 6px); color: var(--color-danger, #b3261e); }",
		".admin__secret { padding: var(--space-3) var(--space-4); border: 1px solid var(--color-success, #1b7f4d); border-radius: var(--radius-md, 6px); color: var(--color-text); }",
		".admin__secretkey { cursor: pointer; font-family: var(--font-mono, monospace); font-size: 0.85em; word-break: break-all; }",
		".admin__confirm { display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap; padding: var(--space-3) var(--space-4); border: 1px solid var(--color-border, var(--color-text-muted)); border-radius: var(--radius-md, 6px); }",
		".admin__rowaction { display: inline-flex; align-items: center; justify-content: center; cursor: pointer; color: var(--color-text-muted); border-radius: var(--radius-sm, 4px); }",
		".admin__rowaction:hover { color: var(--color-danger, #b3261e); }",
		// the .fill wrapper carries the row id (the click's targetId), so it must
		// cover the whole action area — a click landing on the outer div would
		// arrive without a targetId.
		".admin__rowaction .fill { display: flex; width: 100%; height: 100%; align-items: center; justify-content: center; }",
		".admin form { display: flex; flex-direction: column; gap: var(--space-3); max-width: 460px; padding: var(--space-3) 0; }"
	]

	/// The `#section` fragment: the nav row (whose active-section highlight
	/// tracks `section`) plus the section content. The nav rides inside the
	/// fragment so navigation updates it; its buttons register under stable
	/// ids. Called both during the page render (inside the server's render
	/// context — handlers register) and from WS handlers (outside any context —
	/// attributes re-emit without re-registering).
	private func sectionHTML(_ section:AdminSection) -> String {
		let nav = Div(class: "admin__nav") {
			AdminSection.allCases.map { navSection in
				WebUIButton(navSection.label, appearance: navSection == section ? .primary : .ghost, size: .sm, id: "nav-\(navSection.rawValue)")
					.attribute("data-component-id", "nav-\(navSection.rawValue)")
					.attribute("data-event", "click")
			}
		}.markup.html
		let inner:String
		switch section {
			case .overview: inner = overviewView()
			case .users: inner = usersView()
			case .peers: inner = peersView()
			case .transactions: inner = transactionsView()
			case .accessLevels: inner = accessLevelsView()
		}
		return "<div id=\"section\" class=\"admin__section\">" + nav + errorBanner() + (section == .users ? createdUserPanel() : "") + inner + dialogsHTML(section) + "</div>"
	}

	/// The last failed mutation, if any. Rendered on every section render so it
	/// survives live pushes; cleared by navigation and successful actions.
	private func errorBanner() -> String {
		let message:String? = lastError.withLock { $0 }
		guard let message else { return "" }
		return "<div class=\"admin__error\">\(AdminWebUIServer.escapeHTML(message))</div>"
	}

	/// One-time secret handoff for a freshly generated user keypair. Rendered
	/// with the section that follows a successful add-user; any navigation or
	/// further action clears it, since the secret cannot be recovered later.
	private func createdUserPanel() -> String {
		if let byo = createdByoUser.withLock({ $0 }) {
			return "<div class=\"admin__secret\"><strong>New user '\(AdminWebUIServer.escapeHTML(byo))' created with the provided public key.</strong> No secret was generated — the user signs events with the private half on their own machine.</div>"
		}
		guard let created = createdUser.withLock({ $0 }) else { return "" }
		let secret = created.secret
		return "<div class=\"admin__secret\"><strong>New user '\(AdminWebUIServer.escapeHTML(created.name))' created.</strong> " +
			"Copy this base64 secret key now — it is shown only once and cannot be recovered: " +
			"<code data-copy-key=\"\(AdminWebUIServer.escapeHTML(secret))\" class=\"admin__secretkey\" title=\"click to copy\">\(AdminWebUIServer.escapeHTML(secret))</code></div>"
	}

	/// Registers every stable component id with the event router up front.
	///
	/// Handler-generated fragments render outside a `RenderContext`, so they
	/// cannot register (or even emit) minted-id handlers — wiring must not
	/// depend on render context at all. Each interactive element here carries a
	/// fixed id and emits its routing attributes via `.attribute(...)`, while
	/// the matching handler is registered exactly once, here.
	private func registerHandlers() {
		// `.default` session: harmless baseline. The page render additionally
		// registers the same ids into the request's render-token session via
		// registerSessionHandlers(), which is what the client actually routes by.
		registerAll(in: .default)
	}

	/// Registers every stable component id into the current render session.
	/// Must be called from inside the page render's `RenderContext`.
	private func registerSessionHandlers() {
		guard var context = RenderContext.current else { return }
		registerAll(in: context.session)
	}

	private func registerAll(in session:RenderSessionID) {
		let router = self.router
		func add(_ handler:@escaping EventHandler, _ id:String) {
			router.register(handler, for: ComponentID(id), in: session)
		}
		for section in AdminSection.allCases {
			add(navigateHandler(section), "nav-\(section.rawValue)")
		}
		add(openAddHandler("user"), "open-add-user")
		add(openAddHandler("peer"), "open-add-peer")
		add(openAddHandler("access"), "open-add-access")
		add({ [self] event in submitAddUser(event) }, "add-user-form")
		add({ [self] event in submitAddPeer(event) }, "add-peer-form")
		add({ [self] event in submitAddAccessLevel(event) }, "add-access-form")
		add(removeHandler("user"), "remove-user")
		add(removeHandler("peer"), "remove-peer")
		add({ [self] _ in confirmRemoval() }, "confirm-accept")
		add(confirmCancelHandler, "confirm-cancel")
	}

	private func navigateHandler(_ section:AdminSection) -> EventHandler {
		return { [self] _ in
			currentSection.withLock { $0 = section }
			// navigation abandons any in-flight editing state
			addingUser.withLock { $0 = false }
			addingPeer.withLock { $0 = false }
			addingAccess.withLock { $0 = false }
			createdUser.withLock { $0 = nil }
			createdByoUser.withLock { $0 = nil }
			pendingConfirm.withLock { $0 = nil }
			lastError.withLock { $0 = nil }
			return [FragmentUpdate(id: "section", html: sectionHTML(section))]
		}
	}

	private func openAddHandler(_ kind:String) -> EventHandler {
		return { [self] _ in
			switch kind {
				case "user": addingUser.withLock { $0 = true }
				case "peer": addingPeer.withLock { $0 = true }
				case "access": addingAccess.withLock { $0 = true }
				default: break
			}
			let active = currentSection.withLock { $0 }
			return [FragmentUpdate(id: "section", html: sectionHTML(active))]
		}
	}

	private var confirmCancelHandler:EventHandler {
		return { [self] _ in
			pendingConfirm.withLock { $0 = nil }
			lastError.withLock { $0 = nil }
			let active = currentSection.withLock { $0 }
			return [FragmentUpdate(id: "section", html: sectionHTML(active))]
		}
	}

	/// Inline editing surfaces: the add-user / add-peer forms and the removal
	/// confirm panel. Rendered on every section (hidden via CSS when inactive)
	/// so their fixed ids are registered by the page render and present in every
	/// fragment — dynamically-appearing controls would arrive unregistered.
	///
	/// Row-level remove buttons are also stable ids (`remove-user` /
	/// `remove-peer`); the handler reads the row key from the click event's
	/// `targetId` (the enclosing wrapper div carries `user-<key>` /
	/// `peer-<key>`), so one handler serves every row without re-registration.
	private func dialogsHTML(_ section:AdminSection) -> String {
		guard adminKey != nil else { return "" }
		var parts:[String] = []
		let addingU = addingUser.withLock { $0 }
		let addingP = addingPeer.withLock { $0 }
		let addingA = addingAccess.withLock { $0 }
		let pending = pendingConfirm.withLock { $0 }

		// add-user form (only rendered open in the Users section)
		if section == .users {
			parts.append(wrapped(addingU, addUserForm()))
		}
		// add-peer form (only rendered open in the Peers section)
		if section == .peers {
			parts.append(wrapped(addingP, addPeerForm()))
		}
		// add-access-level form (only rendered open in the Access Levels section)
		if section == .accessLevels {
			parts.append(wrapped(addingA, addAccessLevelForm()))
		}

		// hidden registry: keeps `add-user-submit` / `add-peer-submit` /
		// `confirm-accept` / `confirm-cancel` / row-remove button ids registered
		// even when the section rendering them isn't visible.
		var registry = "<div class=\"admin__hidden\">"
		registry += addUserForm()
		registry += addPeerForm()
		registry += addAccessLevelForm()
		registry += confirmPanelHTML(nil)
		registry += removeActionHTML(kind: "user", rowId: "user-registry")
		registry += removeActionHTML(kind: "peer", rowId: "peer-registry")
		registry += openAddHTML(kind: "user", label: "Add user")
		registry += openAddHTML(kind: "peer", label: "Add peer")
		registry += openAddHTML(kind: "access", label: "Add access level")
		registry += "</div>"
		parts.append(registry)

		if let pending {
			parts.append(confirmPanelHTML(pending))
		}
		return parts.joined()
	}

	private func wrapped(_ visible:Bool, _ html:String) -> String {
		return visible ? html : "<div class=\"admin__hidden\">" + html + "</div>"
	}

	private func addUserForm() -> String {
		return Form(method: .get) {
			Heading("Add user", level: .h4)
			Input(name: "userName", placeholder: "user name", required: true)
			Input(name: "readLevels", placeholder: "read access levels (comma-separated names)", value: "")
			Input(name: "writeLevels", placeholder: "write access levels (comma-separated names)", value: "")
			Input(name: "userPublicKey", placeholder: "public key (base64, optional — leave empty to generate keys)")
			WebUIButton("Create user", appearance: .primary, size: .sm)
		}
		.attribute("data-component-id", "add-user-form")
		.attribute("data-event", "submit")
		.markup.html
	}

	private func addPeerForm() -> String {
		return Form(method: .get) {
			Heading("Add peer", level: .h4)
			Input(name: "publicKey", placeholder: "public key (base64)", required: true)
			Input(name: "ip", placeholder: "endpoint IP (optional)")
			Input(name: "port", placeholder: "endpoint port (optional)")
			Input(name: "keepAlive", placeholder: "keep-alive seconds (optional)")
			Select(name: "peerType", options: [SelectOption(value: "tessera", label: "tessera relay"), SelectOption(value: "application", label: "application")], selected: "application")
			WebUIButton("Add peer", appearance: .primary, size: .sm)
		}
		.attribute("data-component-id", "add-peer-form")
		.attribute("data-event", "submit")
		.markup.html
	}

	/// The confirm/cancel pair for a pending removal (nil pending renders the
	/// buttons too — inside the hidden registry — so their ids stay registered).
	private func confirmPanelHTML(_ pending:PendingConfirm?) -> String {
		let message:String
		switch pending {
			case .removeUser(_, let name): message = "Remove user \(name)? This permanently deletes their user record from the database."
			case .removePeer(let key): message = "Remove peer \(AdminWebUIServer.shortKey(key, length: 24))? This edits peer-config.json; the change applies when the relay restarts."
			case nil: message = ""
		}
		return Div(class: pending == nil ? "admin__confirm admin__hidden" : "admin__confirm") {
			Text(message)
			WebUIButton("Remove", appearance: .danger, size: .sm)
				.attribute("data-component-id", "confirm-accept")
				.attribute("data-event", "click")
			WebUIButton("Cancel", appearance: .ghost, size: .sm)
				.attribute("data-component-id", "confirm-cancel")
				.attribute("data-event", "click")
		}
		.markup.html
	}

	/// The row-level remove action: a stable component id (`remove-user` /
	/// `remove-peer`); the inner `.fill` div carries the row key as its html id
	/// (`user-<key>` / `peer-<key>`), which the engine reports back as the
	/// click's `targetId` — one handler serves every row without
	/// re-registration.
	private func removeActionHTML(kind:String, rowId:String) -> String {
		return Div(id: "remove-\(kind)", class: "admin__rowaction") {
			Div(class: "fill") {
				WebUIIcon(.trash, size: .small, title: "remove \(kind)")
			}
			.attribute("id", rowId)
		}
		.attribute("data-component-id", "remove-\(kind)")
		.attribute("data-event", "click")
		.markup.html
	}

	/// The row-level remove handler: reads the row key from the click event's
	/// `targetId` (`user-<key>` / `peer-<key>` wrapper divs) and stages a
	/// confirm panel.
	private func removeHandler(_ kind:String) -> EventHandler {
		return { [self] event in
			guard let targetId = event.string("targetId"), targetId.hasPrefix("\(kind)-") else { return [] }
			let key = String(targetId.dropFirst(kind.count + 1))
			switch kind {
				case "user":
					let users = loadUsers()
					let name = users.first { $0.publicKey == key }?.name ?? "(unnamed)"
					pendingConfirm.withLock { $0 = .removeUser(key: key, name: name) }
				case "peer":
					pendingConfirm.withLock { $0 = .removePeer(key: key) }
				default: break
			}
			lastError.withLock { $0 = nil }
			let active = currentSection.withLock { $0 }
			return [FragmentUpdate(id: "section", html: sectionHTML(active))]
		}
	}

	/// Executes the pending removal (user record from the database, or the peer
	/// from peer-config.json) and re-renders the section.
	private func confirmRemoval() -> [FragmentUpdate] {
		let pending = pendingConfirm.withLock { $0 }
		defer { pendingConfirm.withLock { $0 = nil } }
		do {
			switch pending {
				case .removeUser(let key, _):
					guard let adminKey else { throw AdminEditError.notPermitted }
					let publicKey = try AdminWebUIServer.decodeKey(key)
					try db.adminDeleteUser(publicKey: publicKey, logLevel: logger.logLevel)
				case .removePeer(let key):
					let jsonURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
					try editConfig(at: jsonURL) { cfg in
						let decoded = try AdminWebUIServer.decodeKey(key)
						cfg.peers.removeAll { $0.publicKey == decoded }
					}
				case nil: break
			}
			lastError.withLock { $0 = nil }
		} catch {
			logger.warning("removal failed: \(error)")
			lastError.withLock { $0 = (error as? AdminEditError)?.userMessage ?? String(describing: error) }
		}
		let active = currentSection.withLock { $0 }
		return [FragmentUpdate(id: "section", html: sectionHTML(active))]
	}

	/// `--admin-key` is a root credential (same trust boundary as
	/// `create-unbounded-admin`), so a key without a user record in this
	/// database is bootstrapped as a full-access user on first mutation.
	/// Without this, `scribeNewEvent` rejects every admin action with
	/// `userDoesNotExist`.
	private func ensureAdminUser(publicKey:PublicKey, signingKey:MemoryGuarded<RAW_ed25519.PrivateKey>) throws {
		let known = (try? db.adminListUsers()) ?? []
		let keyString = String(RAW_base64.encode(publicKey))
		guard !known.contains(where: { $0.publicKey == keyString }) else { return }
		let event = try UnsignedEvent(publicKey: publicKey, tags: [StringTag(name: "userName", value: "Admin")!, ReadAccessLevels(value: UserAccessLevel(accessLevels: Array(UInt8.min...UInt8.max))), WriteAccessLevels(value: UserAccessLevel(accessLevels: Array(UInt8.min...UInt8.max)))], application: 0, kind: TesseraKinds.user.value, content: ByteBuffer()).sign(as: signingKey)
		try db.scribeNewUser(signedEvent: event, logLevel: logger.logLevel)
		logger.warning("bootstrapped missing admin user record for --admin-key (full access)")
	}

	/// Creates a user: generates a fresh keypair for the new user, signs a
	/// kind-0 event with it and scribes it. Access-level names resolve against
	/// the database's kind-1 access-level events; unknown names fail the
	/// mutation with a banner. The generated secret is surfaced to the admin
	/// exactly once (it cannot be recovered).
	private func submitAddUser(_ event:EventData) -> [FragmentUpdate] {
		defer {
			addingUser.withLock { $0 = false }
			// note: createdUser/createdByoUser deliberately persist after this
			// returns — the one-time secret panel must survive later poll pushes
			// (broadcastLoop skips pushing while it is visible) until navigation.
		}
		do {
			guard adminKey != nil else { throw AdminEditError.notPermitted }
			guard let name = event.string("userName"), !name.isEmpty else { throw AdminEditError.missingField("user name") }
			let readLevels = try resolveLevels(event.string("readLevels") ?? "")
			let writeLevels = try resolveLevels(event.string("writeLevels") ?? "")

			// bring-your-own key: if a public key is supplied the profile is
			// authored under it and no secret is generated. The signing key is
			// a throwaway — the user's private half lives on their machine.
			let publicKey:RAW_dh25519.PublicKey
			var signingKey:MemoryGuarded<RAW_ed25519.PrivateKey>
			var secretBase64:String? = nil
			if let provided = event.string("userPublicKey"), !provided.isEmpty {
				publicKey = try AdminWebUIServer.decodeKey(provided)
				let throwaway = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
				(_, signingKey) = try RAW_ed25519.generateKeys(secretKey: throwaway)
			} else {
				let secret = try MemoryGuarded<RAW_dh25519.PrivateKey>.new()
				(publicKey, signingKey) = try RAW_ed25519.generateKeys(secretKey: secret)
				secretBase64 = String(RAW_base64.encode(secret))
			}
			let signed = try UnsignedEvent(publicKey: publicKey, tags: [StringTag(name: "userName", value: name)!, ReadAccessLevels(value: UserAccessLevel(accessLevels: readLevels)), WriteAccessLevels(value: UserAccessLevel(accessLevels: writeLevels))], application: 0, kind: TesseraKinds.user.value, content: ByteBuffer()).sign(as: signingKey)
			try db.scribeNewUser(signedEvent: signed, logLevel: logger.logLevel)
			if let secretBase64 {
				createdUser.withLock { $0 = (name, secretBase64) }
			} else {
				createdByoUser.withLock { $0 = name }
			}
			lastError.withLock { $0 = nil }
		} catch {
			logger.warning("add user failed: \(error)")
			let message:String
			if error is LMDBError {
				message = "a user with this public key already exists"
			} else {
				message = (error as? AdminEditError)?.userMessage ?? String(describing: error)
			}
			lastError.withLock { $0 = message }
		}
		return [FragmentUpdate(id: "section", html: sectionHTML(.users))]
	}

	/// Adds a peer to peer-config.json (deduplicated by public key). The relay
	/// only reads the file at startup, so the section carries a restart note.
	private func submitAddPeer(_ event:EventData) -> [FragmentUpdate] {
		defer { addingPeer.withLock { $0 = false } }
		do {
			guard let keyString = event.string("publicKey"), !keyString.isEmpty else { throw AdminEditError.missingField("public key") }
			let publicKey = try AdminWebUIServer.decodeKey(keyString)
			let ipAddress = event.string("ip")
			let port = event.string("port").flatMap { Int($0) }
			let keepAlive = event.string("keepAlive").flatMap { Int64($0) }.map { TimeAmount.seconds($0) }
			let isTessera = event.string("peerType") == "tessera"
			let jsonURL = URL(fileURLWithPath: configurationPath.appendingPathComponent("peer-config.json").path())
			try editConfig(at: jsonURL) { cfg in
				if let existing = cfg.peers.firstIndex(where: { $0.publicKey == publicKey }) {
					cfg.peers[existing] = TesseraPeer(publicKey: publicKey, ipAddress: ipAddress, port: port, internalKeepAlive: keepAlive, isTessera: isTessera, inboundData: nil)
				} else {
					cfg.peers.append(TesseraPeer(publicKey: publicKey, ipAddress: ipAddress, port: port, internalKeepAlive: keepAlive, isTessera: isTessera, inboundData: nil))
				}
			}
			lastError.withLock { $0 = nil }
		} catch {
			logger.warning("add peer failed: \(error)")
			lastError.withLock { $0 = (error as? AdminEditError)?.userMessage ?? String(describing: error) }
		}
		return [FragmentUpdate(id: "section", html: sectionHTML(.peers))]
	}

	/// Creates an access level: signs a kind-1 access-level event with the
	/// configured admin key (`perm` + `permName` tags) and scribes it.
	/// Duplicate level numbers or names are rejected so `resolveLevels` stays
	/// unambiguous.
	private func submitAddAccessLevel(_ event:EventData) -> [FragmentUpdate] {
		defer { addingAccess.withLock { $0 = false } }
		do {
			guard let adminKey else { throw AdminEditError.notPermitted }
			guard let name = event.string("levelName"), !name.isEmpty else { throw AdminEditError.missingField("access level name") }
			guard let indexString = event.string("levelIndex"), let index = UInt8(indexString) else { throw AdminEditError.missingField("access level index (0-255)") }
			let existing = loadAccessLevels()
			guard !existing.contains(where: { $0.level == index }) else { throw AdminEditError.duplicateLevel(index) }
			guard !existing.contains(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) else { throw AdminEditError.duplicateLevelName(name) }

			guard let secretData = try? RAW_base64.decode(adminKey), secretData.count == 32 else {
				throw AdminEditError.invalidKey
			}
			let dhKey = try secretData.withUnsafeBytes { ptr -> MemoryGuarded<RAW_dh25519.PrivateKey> in
				guard let guarded = MemoryGuarded<RAW_dh25519.PrivateKey>(RAW_decode: ptr) else {
					throw AdminEditError.invalidKey
				}
				return guarded
			}
			let (publicKey, signingKey) = try RAW_ed25519.generateKeys(secretKey: dhKey)
			try ensureAdminUser(publicKey: publicKey, signingKey: signingKey)
			let signed = try UnsignedEvent(publicKey: publicKey, tags: [AccessLevelTag(value: RAW_byte(RAW_native: index)), AccessLevelNameTag(value: Encoded.String(name))], application: 0, kind: TesseraKinds.accessLevel.value, content: ByteBuffer()).sign(as: signingKey)
			try db.scribeNewEvent(signedEvent: signed, logLevel: logger.logLevel)
			lastError.withLock { $0 = nil }
		} catch {
			logger.warning("add access level failed: \(error)")
			lastError.withLock { $0 = (error as? AdminEditError)?.userMessage ?? String(describing: error) }
		}
		return [FragmentUpdate(id: "section", html: sectionHTML(.accessLevels))]
	}

	private func addAccessLevelForm() -> String {
		return Form(method: .get) {
			Heading("Add access level", level: .h4)
			Input(name: "levelIndex", placeholder: "level index (0-255)", required: true)
			Input(name: "levelName", placeholder: "access level name", required: true)
			WebUIButton("Create access level", appearance: .primary, size: .sm)
		}
		.attribute("data-component-id", "add-access-form")
		.attribute("data-event", "submit")
		.markup.html
	}

	/// Resolves a comma-separated access-level name list into level numbers.
	private func resolveLevels(_ raw:String) throws -> [UInt8] {
		let names = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
		guard !names.isEmpty else { return [] }
		let known = loadAccessLevels()
		var levels:[UInt8] = []
		for name in names {
			guard let match = known.first(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) else {
				throw AdminEditError.unknownLevel(name)
			}
			levels.append(match.level)
		}
		return levels
	}

	enum AdminEditError:Swift.Error {
		case notPermitted, invalidKey, missingField(String), unknownLevel(String), duplicateLevel(UInt8), duplicateLevelName(String)

		/// Human-readable banner text for the dashboard error surface.
		var userMessage:String {
			switch self {
				case .notPermitted: return "editing is not available (start the webui with --admin-key)"
				case .invalidKey: return "the configured admin key is not a valid base64 32-byte secret"
				case .missingField(let field): return "missing field: \(field)"
				case .unknownLevel(let name): return "unknown access level name: \(name)"
				case .duplicateLevel(let index): return "an access level with index \(index) already exists"
				case .duplicateLevelName(let name): return "an access level named '\(name)' already exists"
			}
		}
	}

	/// Minimal HTML escaping for error/state text interpolated into fragments.
	private static func escapeHTML(_ raw:String) -> String {
		return raw.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
	}

	/// Decodes a base64 WireGuard public key (mirrors `PublicKey(argument:)`
	/// from `Arguments.swift`).
	fileprivate static func decodeKey(_ base64:String) throws -> PublicKey {
		guard let bytes = try? RAW_base64.decode(base64), bytes.count == 32 else {
			throw AdminEditError.invalidKey
		}
		return bytes.withUnsafeBytes { ptr in
			PublicKey(RAW_decode: ptr)!
		}
	}

	/// The body of the whole page (header + the current section). Runs inside
	/// the server's render pass, so delegated handlers self-register.
	private func pageBody(signedInAs:String?) -> String {
		// The client routes WS events by its render-token session, so the
		// handlers must be registered in *that* session — not just `.default`.
		// This runs inside the server-owned RenderContext (see WebUIServer's
		// page render), which is the session the page will talk from.
		registerSessionHandlers()
		let initial = currentSection.withLock { $0 }
		return Div(class: "admin") {
			Header(class: "admin__header") {
				Div(class: "admin__header-row") {
					Heading("Tessera Admin", level: .h1)
					if let signedInAs {
						Div(class: "admin__session") {
							Text("signed in as \(signedInAs)")
							Link("logout", href: "/logout")
						}
					}
				}
				Text("relay database: \(databasePath.path())")
			}
			Raw(UnsafeMarkup.trusted(sectionHTML(initial)))
		}.markup.html
	}

	/// The request's cookies, parsed from the `Cookie` header.
	///
	/// NOTE: no-webui 2.1.0 does not populate `HTTPRequest.cookies` (the
	/// field exists but the decoder never fills it), so this parses the raw
	/// header here. If the framework starts populating `cookies`, this can
	/// switch to it.
	fileprivate static func cookies(from request:HTTPRequest) -> [String: String] {
		var out:[String: String] = [:]
		for header in request.headers["Cookie"] {
			for pair in header.split(separator: ";") {
				let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: true)
				guard parts.count == 2 else { continue }
				out[parts[0].trimmingCharacters(in: .whitespaces)] = parts[1].trimmingCharacters(in: .whitespaces).removingPercentEncoding ?? String(parts[1])
			}
		}
		return out
	}

	/// Answers a dashboard page request: session-gated when auth is enabled,
	/// the login page when there is no valid session, and an open dashboard in
	/// read-only mode.
	private func dashboardPage(request:HTTPRequest) -> AdminPage {
		AdminPage { buffer in
			guard let auth = self.auth else {
				// read-only mode: the dashboard is public, nothing to protect.
				AdminDocument(server: self, renderToken: request.renderToken.value, signedInAs: nil).render(into: &buffer)
				return
			}
			if let username = auth.session(for: AdminWebUIServer.cookies(from: request))?.username {
				AdminDocument(server: self, renderToken: request.renderToken.value, signedInAs: username).render(into: &buffer)
			} else {
				Self.loginDocument(failed: false).render(into: &buffer)
			}
		}
	}

	/// The static login page. No engine script — an unauthenticated visitor
	/// gets plain HTML and a native form POST; the WebSocket only exists for
	/// authenticated sessions.
	fileprivate static func loginDocument(failed:Bool) -> HTMLDocument {
		let body = Div(class: "login") {
			Div(class: "login__card") {
				Heading("Tessera Admin", level: .h1)
				if failed {
					Div(class: "login__error") { Text("the admin secret key did not match.") }
				}
				Form(action: "/login", method: .post) {
					Label("username", for: "username")
					Input(id: "username", name: "username", type: .text, required: true, attributes: [("autocomplete", "username")])
					Label("admin secret key", for: "secretKey")
					Input(id: "secretKey", name: "secretKey", type: .password, required: true, attributes: [("autocomplete", "off")])
					Button("sign in", class: "login__submit")
				}
			}
		}.markup.html
		return HTMLDocument(
			title: "Tessera Admin — sign in",
			body: .trusted(body),
			rawStyles: ["""
			.login { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: var(--space-4, 1rem); }
			.login__card { width: 22rem; display: flex; flex-direction: column; gap: var(--space-2, 0.5rem); padding: var(--space-5, 2rem); border: 1px solid var(--color-border, #333); border-radius: var(--radius-md, 8px); background: var(--color-surface, #16181d); }
			.login__card h1 { font-size: 1.15rem; margin: 0 0 var(--space-2, 0.5rem); }
			.login__card label { display: block; font-size: 0.8rem; color: var(--color-text-muted, #888); margin: var(--space-2, 0.5rem) 0 0.2rem 0; }
			.login__card input { display: block; width: 100%; box-sizing: border-box; padding: 0.45rem 0.6rem; border: 1px solid var(--color-border, #333); border-radius: var(--radius-sm, 4px); background: var(--color-bg, #0d0e11); color: var(--color-text, #eee); font: inherit; }
			.login__card input:focus { outline: 1px solid var(--color-accent, #4c8dff); }
			.login__card button { margin-top: var(--space-3, 1rem); padding: 0.5rem 0.75rem; border: none; border-radius: var(--radius-sm, 4px); background: var(--color-accent, #4c8dff); color: #fff; cursor: pointer; }
			.login__error { font-size: 0.8rem; color: var(--color-danger, #e5534b); }
			"""],
			includeRuntime: false,
			stylesheetURL: DesignSystemAssets.stylesheetURL
		)
	}

	/// A section heading (live pushes keep the data fresh — no manual refresh).
	private func sectionHeader(_ title:String) -> any View {
		return Heading(title, level: .h3)
	}

	/// The request path the copy-to-clipboard helper script is served at.
	static let copyScriptPath = "/ui/admin-copy.js"
	/// The page's copy helper: one delegated listener copies any element carrying
	/// `data-copy-key` and flashes it via the `.copied` class. Delegated on
	/// `document`, so it keeps working after live-push fragment replacement.
	static let copyScript = """
	function copyKey(b){navigator.clipboard.writeText(b.getAttribute('data-copy-key')).then(function(){b.classList.add('copied');setTimeout(function(){b.classList.remove('copied')},1200)}).catch(function(){})}
	document.addEventListener('click',function(e){var b=e.target.closest('[data-copy-key]');if(b)copyKey(b)});
	document.addEventListener('keydown',function(e){if(e.key!=='Enter'&&e.key!==' ')return;var b=e.target.closest('[data-copy-key]');if(b){e.preventDefault();copyKey(b)}});
	"""
	static let copyScriptAsset = WebUIServerAsset(path: copyScriptPath, body: .text(copyScript), contentType: "text/javascript")

	/// A truncated public key with a copy icon; the icon carries the full key in
	/// `data-copy-key` (handled client-side by `copyScript`, not over the
	/// WebSocket) and the full key in `title` for hover inspection.
	private func copyKeyCell(_ key:String) -> any View {
		return Div(class: "admin__keycell") {
			Text(AdminWebUIServer.shortKey(key))
			Div(class: "copy-key") {
				WebUIIcon(.copy, size: .small, title: "copy public key")
			}
			.attribute("data-copy-key", key)
			.attribute("role", "button")
			.attribute("tabindex", "0")
			.attribute("aria-label", "copy public key")
		}
	}

	private func overviewView() -> String {
		let stats = loadStats()
		guard let stats else {
			return WebUICard(elevation: .outlined) { WebUIEmptyState(icon: .inbox, title: "No statistics", message: "The database query failed or the database is empty.") }.markup.html
		}
		let peers = loadPeers()
		return WebUICard(elevation: .outlined) {
			sectionHeader("Overview")
			Div(class: "admin__statgrid") {
				WebUIStat(label: "Total events", value: String(stats.totalEvents))
				WebUIStat(label: "Users", value: String(stats.userCount))
				WebUIStat(label: "Tessera relays", value: String(peers.tesserae))
				WebUIStat(label: "Applications", value: String(peers.applications))
				WebUIStat(label: "Events (24h)", value: String(stats.last24h))
				WebUIStat(label: "Database size", value: AdminWebUIServer.formatBytes(stats.databaseFileSize))
			}
			Heading("Events per kind", level: .h4)
			AdminWebUIServer.kindTable(stats)
			Heading("Recent peer transactions", level: .h4)
			AdminWebUIServer.transactionTable(loadTransactions(limit: 8))
		}.markup.html
	}

	private static func kindTable(_ stats:AdminEventStats) -> any View {
		let sorted = stats.perKind.sorted { ($0.value, $1.key) > ($1.value, $0.key) }.prefix(12)
		let rows:[[any View]] = sorted.map { (kind, count) in
			let label = kind == Int(TesseraKinds.user.value) ? " (users)" : kind == Int(TesseraKinds.accessLevel.value) ? " (access levels)" : kind == 5 ? " (deletions)" : ""
			return [Text("\(kind)\(label)"), Text(String(count))]
		}
		return WebUITable(headers: ["Kind", "Count"], rows: rows, alignments: [.leading, .trailing])
	}

	private func usersView() -> String {
		let users = loadUsers()
		let canEdit = adminKey != nil
		let rows:[[any View]] = users.map { user in
			let status = AdminWebUIServer.userStatus(lastActivity: user.lastActivity, windowDays: activityWindowDays)
			var row:[any View] = [
				Text(user.name ?? "(unnamed)"),
				copyKeyCell(user.publicKey),
				Text(AdminUserInfo.format(user.readAccessLevels)),
				Text(AdminUserInfo.format(user.writeAccessLevels)),
				Text(String(user.eventCount)),
				Text(AdminWebUIServer.formatDate(user.lastActivity)),
				WebUIBadge(status.label, tone: status.tone, size: .sm)
			]
			if canEdit {
				row.append(Raw(UnsafeMarkup.trusted(removeActionHTML(kind: "user", rowId: "user-\(user.publicKey)"))))
			}
			return row
		}
		var headers = ["Name", "Public Key", "Read", "Write", "Events", "Last Seen", "Status"]
		if canEdit { headers.append("Actions") }
		return WebUICard(elevation: .outlined) {
			sectionHeader("Users (\(users.count))")
			Text("A user is 'active' when their most recent event is newer than \(activityWindowDays) \(activityWindowDays == 1 ? "day" : "days").")
			WebUITable(
				headers: headers,
				rows: rows,
				emptyState: .init(title: "No users", message: "No users are registered in this database yet.")
			)
			if canEdit {
				Raw(UnsafeMarkup.trusted(openAddHTML(kind: "user", label: "Add user")))
			} else {
				Text("Read-only: restart the dashboard with --admin-key <base64 admin secret> to add or remove users.")
			}
		}.markup.html
	}

	/// The "add user/peer" toggle button (fixed id; also present in the hidden
	/// registry so it stays registered across section switches).
	private func openAddHTML(kind:String, label:String) -> String {
		return WebUIButton(label, appearance: .secondary, size: .sm)
			.attribute("data-component-id", "open-add-\(kind)")
			.attribute("data-event", "click")
			.markup.html
	}

	private func peersView() -> String {
		let peers = loadPeers()
		let canEdit = adminKey != nil
		let rows:[[any View]] = peers.rows.map { peer in
			var row:[any View] = [
				copyKeyCell(peer.key),
				WebUIBadge(peer.isTessera ? "tessera relay" : "application", tone: peer.isTessera ? .info : .neutral, size: .sm),
				Text(peer.endpoint),
				Text(peer.keepAlive)
			]
			if canEdit {
				row.append(Raw(UnsafeMarkup.trusted(removeActionHTML(kind: "peer", rowId: "peer-\(peer.key)"))))
			}
			return row
		}
		var headers = ["Public Key", "Type", "Endpoint", "Keep-alive"]
		if canEdit { headers.append("Actions") }
		return WebUICard(elevation: .outlined) {
			sectionHeader("Peers (\(peers.rows.count))")
			Text("Peers are loaded from peer-config.json when the relay starts; changes made here apply on restart.")
			WebUITable(
				headers: headers,
				rows: rows,
				emptyState: .init(title: "No peers", message: "No peers are configured for this relay.")
			)
			if canEdit {
				Raw(UnsafeMarkup.trusted(openAddHTML(kind: "peer", label: "Add peer")))
			}
		}.markup.html
	}

	private func transactionsView() -> String {
		let records = loadTransactions(limit: 50)
		return WebUICard(elevation: .outlined) {
			sectionHeader("Recent peer transactions (\(records.count) most recent)")
			AdminWebUIServer.transactionTable(records)
		}.markup.html
	}

	private static func transactionTable(_ records:[PeerTransactionRecord]) -> any View {
		let rows:[[any View]] = records.map { record in
			let tone:Tone
			switch record.type {
				case "event": tone = .success
				case "req": tone = .info
				case "sync": tone = .primary
				default: tone = .neutral
			}
			return [
				Text(record.timestamp.formatted(date: .abbreviated, time: .standard)),
				Text(record.direction),
				WebUIBadge(record.type, tone: tone, size: .sm),
				Text(shortKey(record.peer)),
				Text(record.detail)
			]
		}
		return WebUITable(
			headers: ["Time", "Direction", "Type", "Peer", "Detail"],
			rows: rows,
			emptyState: .init(title: "No transactions", message: "Records appear once the relay is running and peers exchange traffic.")
		)
	}

	private func accessLevelsView() -> String {
		let levels = loadAccessLevels()
		let rows:[[any View]] = levels.sorted(by: { $0.level < $1.level }).map { level in
			return [
				Text(String(level.level)),
				Text(level.name),
				Text(AdminWebUIServer.formatDate(level.date)),
				Text(AdminWebUIServer.shortKey(level.author))
			]
		}
		return WebUICard(elevation: .outlined) {
			sectionHeader("Access levels (\(levels.count))")
			if adminKey != nil {
				Div {
					Raw(UnsafeMarkup.trusted(openAddHTML(kind: "access", label: "Add access level")))
				}.attribute("class", "admin__formrow")
			}
			WebUITable(
				headers: ["Level", "Name", "Created", "Author"],
				rows: rows,
				emptyState: .init(title: "No access levels", message: "No access levels are defined in this database yet.")
			)
		}.markup.html
	}

	// MARK: server

	/// The per-request page document. Rendering happens inside the server's
	/// render context, so the queries run fresh on every page load and the
	/// controls register into the connection's render session. The engine
	/// script + `webui-config` meta (carrying the render token that binds WS
	/// frames to this session) are emitted automatically.
	/// A concrete `BufferRendering` that delegates to whichever document the
	/// route decided on (dashboard vs login). `Route.page` infers one concrete
	/// type per route, so the two document shapes need a shared shell.
	private struct AdminPage:BufferRendering {
		let renderBody:@Sendable (inout HTMLBuffer) -> Void
		func render(into buffer:inout HTMLBuffer) {
			renderBody(&buffer)
		}
	}

	private struct AdminDocument:BufferRendering {
		let server:AdminWebUIServer
		let renderToken:String
		let signedInAs:String?

		func render(into buffer:inout HTMLBuffer) {
			let document = WebUIDocument(
				title: "Tessera Admin",
				body: .trusted(server.pageBody(signedInAs: signedInAs)),
				headContent: HeadContent.script(src: AdminWebUIServer.copyScriptPath),
				runtimeConfig: renderToken.isEmpty ? nil : RuntimeConfig(renderToken: renderToken),
				rawStyles: AdminWebUIServer.layoutStyles
			)
			buffer.append(document.markup.html)
		}
	}

	/// Binds the HTTP + WebSocket server and serves until cancelled.
	func run() async throws {
		DesignSystemAssets.prewarm()
		registerHandlers()
		let pageRouter = Router {
			Route.page("/") { [self] request in
				AdminPage { buffer in
					self.dashboardPage(request: request).render(into: &buffer)
				}
			}
			Route.page("/index.html") { [self] request in
				AdminPage { buffer in
					self.dashboardPage(request: request).render(into: &buffer)
				}
			}
			Route.page("/login") { [self] request in
				AdminPage { buffer in
					if let auth = self.auth, auth.session(for: AdminWebUIServer.cookies(from: request)) != nil {
						// already signed in — straight to the dashboard.
						AdminDocument(server: self, renderToken: request.renderToken.value, signedInAs: nil).render(into: &buffer)
					} else {
						Self.loginDocument(failed: request.query["error"] == "key").render(into: &buffer)
					}
				}
			}
			Route.post("/login") { [self] request in
				guard let auth = self.auth else {
					// read-only mode has no login; the dashboard is public.
					return HTTPResponse(body: .redirect(to: "/"))
				}
				let form:FormValues? = if case .form(let values) = request.body { values } else { nil }
				let username = form?.string("username") ?? ""
				let secretKey = form?.string("secretKey") ?? ""
				if let token = auth.login(username: username, secretKey: secretKey) {
					let attributes = HTTPCookie.Attributes(
						maxAge: Int(AdminAuth.sessionLifetime),
						path: "/",
						httpOnly: true,
						sameSite: .lax
					)
					let cookie = HTTPCookie(name: AdminAuth.cookieName, value: token, attributes: attributes)
					return HTTPResponse(cookies: [cookie], body: .redirect(to: "/"))
				}
				// blunt brute force a little before re-serving the form.
				try? await Task.sleep(for: .milliseconds(400))
				return HTTPResponse(body: .redirect(to: "/login?error=key"))
			}
			Route.get("/logout") { [self] request in
				if let auth, let token = AdminWebUIServer.cookies(from: request)[AdminAuth.cookieName] {
					auth.logout(token: token)
				}
				let attributes = HTTPCookie.Attributes(maxAge: 0, path: "/", httpOnly: true)
				let cookie = HTTPCookie(name: AdminAuth.cookieName, value: "", attributes: attributes)
				return HTTPResponse(cookies: [cookie], body: .redirect(to: auth == nil ? "/" : "/login"))
			}
		}
		let server = WebUIServer(
			router: pageRouter,
			eventRouter: router,
			// `requireRenderToken` refuses frames the page render never minted:
			// without it, a rogue WebSocket could drive the shared `.default`
			// session's handlers (and receive broadcast pushes) without ever
			// having loaded the authenticated page.
			config: WebUIServerConfig(host: host, port: port, pagePath: "/", assets: [Self.copyScriptAsset], requireRenderToken: auth != nil),
			logger: logger
		)
		logger.info("admin dashboard on http://\(host):\(port) (ws://\(host):\(port)/ws)")
		try await withThrowingTaskGroup(of: Void.self) { group in
			group.addTask { [self] in
				try await server.start()
			}
			if pollInterval > 0 {
				group.addTask { [self] in
					await broadcastLoop(server)
				}
			}
			// the poller never throws (cancellation is handled internally), so the
			// first completion is either the server stopping or a bind failure —
			// either way, stop the rest and propagate the outcome.
			try await group.next()
			group.cancelAll()
			try await group.waitForAll()
		}
	}

	/// Re-renders the currently visible section on an interval and pushes it to
	/// every connected client via `WebUIServer.broadcast`. Fragment html built
	/// outside a RenderContext re-emits the stable `data-component-id` attributes
	/// without re-registering, so pushes never disturb the event router.
	private func broadcastLoop(_ server:WebUIServer) async {
		while !Task.isCancelled {
			do {
				try await Task.sleep(for: .seconds(pollInterval))
			} catch {
				break // cancelled
			}
			let before = currentSection.withLock { $0 }
			// skip the push during critical moments — a push replaces the section
			// fragment, which would wipe in-progress form input, break a pending
			// confirm, or destroy a text selection while the one-time secret
			// panel is being copied. the next poll after it clears catches up.
			guard !isCriticalMoment() else { continue }
			let html = sectionHTML(before)
			// re-check after rendering: the user may have opened a form or the
			// panel may have appeared while the html was being built — pushing
			// now would replace freshly-typed input or a just-shown secret.
			guard !isCriticalMoment() else { continue }
			// skip the push if the user navigated while the html was rendering;
			// the next poll renders the new section anyway.
			let after = currentSection.withLock { $0 }
			guard after == before else { continue }
			await server.broadcast([FragmentUpdate(id: "section", html: html)])
		}
	}

	/// True whenever replacing the section fragment would disturb the user:
	/// an add form is open, a removal confirm is staged, or the one-time
	/// secret/created-user panel is visible (it must stay selectable so the
	/// private key can be copied — a fragment swap kills the selection even
	/// though the content itself is stable across re-renders).
	private func isCriticalMoment() -> Bool {
		if addingUser.withLock({ $0 }) { return true }
		if addingPeer.withLock({ $0 }) { return true }
		if addingAccess.withLock({ $0 }) { return true }
		if pendingConfirm.withLock({ $0 }) != nil { return true }
		if createdUser.withLock({ $0 }) != nil { return true }
		if createdByoUser.withLock({ $0 }) != nil { return true }
		return false
	}
}

#endif
