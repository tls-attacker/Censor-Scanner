package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.RecordManipulationType
import de.rub.nds.censor.core.util.RecordCreator
import de.rub.nds.censor.core.util.Util.applyManipulationType
import de.rub.nds.tlsattacker.core.record.Record

/**
 * Manipulation for inserting a record in front of or after the records of the correct message
 */
class RecordInjectionManipulation(val recordTypeBefore: RecordManipulationType? = null, val recordTypeAfter: RecordManipulationType? = null) : TlsManipulation() {
    override fun afterAllRecordsCreation(recordCreator: RecordCreator, records: MutableList<Record>) {
        recordCreator.insertRecordOfTypeBefore = recordTypeBefore
        recordCreator.insertRecordOfTypeAfter = recordTypeAfter

        if (recordTypeBefore != null) {
            val recordToAddBefore = Record().apply { applyManipulationType(recordTypeBefore) }
            records.add(0,recordToAddBefore)
        }

        if (recordTypeAfter != null) {
            val recordToAddAfter = Record().apply { applyManipulationType((recordTypeAfter)) }
            records.add(recordToAddAfter)
        }
    }

    override val name: String
        get() = "record_fragmentation(recordTypeBefore=$recordTypeBefore, recordTypeAfter=$recordTypeAfter)"
}