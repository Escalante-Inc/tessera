
public enum SignedNoteError : Error {
	case cantStoreEphemeralEvent
	
	case invalidKind5Tag
	case invalidKind5PublicKey
	
	case invalidParameterizedEvent
	
	case invalidUserNote
}
