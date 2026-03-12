/// # User Access Levels
///
/// There are 256 access levels each with a range of eligible kinds.
/// Access Level 0: [40_000, 79_999]
/// Access Level 1: [80_000, 119_999]
/// ...
/// Access Level 255: [10,240,000 , 10,279,999]
///
/// # NOSTR Kinds
///
/// Inside each `40_000` range of kinds per access level:
/// - The first `10_000` (i.e. [0, 9_999]) represent non-replaceable events.
/// - The second `5_000` (i.e. [10_000, 14_999]) represent replaceable events via the PK (publicKey, kind).
/// - The third `10_000` (i.e. [15_000, 24_999]) represent the replaceable events via the PK (kind, d-tag).
/// - The fourth `10_000` (i.e. [25_000, 29_999]) represent ephemeral events.
/// - The fifth `10_000` (i.e [30_000, 39_999]) represent replaceable events via the PK (publicKey, kind, d-tag).
public enum NostrKindCategory {
	case nonReplaceable
	case replaceablePK
	case replaceablePKDTag
	case ephemeral
	case replaceablePKKindDTag
	case unknown

	/// Initialize from a raw kind integer
	public init(kind: UInt32) {
		switch kind {
		case 0..<10_000:
			self = .nonReplaceable
		case 10_000..<15_000:
			self = .replaceablePK
		case 15_000..<25_000:
			self = .replaceablePKDTag
		case 25_000..<30_000:
			self = .ephemeral
		case 30_000..<40_000:
			self = .replaceablePKKindDTag
		default:
			self = .unknown
		}
	}

	/// Return the range of kinds for this category
	public var range: ClosedRange<UInt32> {
		switch self {
		case .nonReplaceable: return 0...9_999
		case .replaceablePK: return 10_000...14_999
		case .replaceablePKDTag: return 15_000...24_999
		case .ephemeral: return 25_000...29_999
		case .replaceablePKKindDTag: return 30_000...39_999
		case .unknown: return UInt32.min...UInt32.max
		}
	}
}
