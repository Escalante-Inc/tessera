public enum TesseraKinds {
	case user
	case accessLevel
	
	public var value:UInt32 {
		switch self {
			case .user: 0
			case .accessLevel: 1
		}
	}
}
