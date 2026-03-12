public enum AccessLevelError: Swift.Error {
	case userDoesNotExist
	case userHasNoAccessLevels
	case invalidReadAccess
	case invalidWriteAccess
}
