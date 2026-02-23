import Logging

extension Logger.Message {
	static func red(_ text: String) -> Logger.Message {
		Logger.Message(stringLiteral: "\u{001B}[0;31m\(text)\u{001B}[0;0m")
	}

	static func green(_ text: String) -> Logger.Message {
		Logger.Message(stringLiteral: "\u{001B}[0;32m\(text)\u{001B}[0;0m")
	}
	
	static func yellow(_ text: String) -> Logger.Message {
		Logger.Message(stringLiteral: "\u{001B}[0;33m\(text)\u{001B}[0;0m")
	}
	
	static func orange(_ text: String) -> Logger.Message {
		Logger.Message(stringLiteral: "\u{001B}[38;5;208m\(text)\u{001B}[0;0m")
	}
}
