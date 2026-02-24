import Logging
import QuickLMDB

extension TesseraDB {
	public var eventCount: Int {
		do {
			let newTrans = try Transaction(env:env, readOnly:true)
			let stats = try signedEvents.dbStatistics(tx: newTrans)
			return stats.ms_entries
		} catch let error {
			log.error(Logger.Message.red("failed to retrieve event stats due to internal error"), metadata: ["error":"\(error)"])
		}
		return -1
	}
}
