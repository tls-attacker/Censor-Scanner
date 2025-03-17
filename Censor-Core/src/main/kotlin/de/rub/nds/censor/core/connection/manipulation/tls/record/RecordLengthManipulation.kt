package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants
import de.rub.nds.censor.core.util.IntegerMultiplyWithMaximumModification
import de.rub.nds.modifiablevariable.ModifiableVariableFactory
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import de.rub.nds.tlsattacker.core.record.Record

/**
 * Invalidates the record length of all TLS records that contain a certain message.
 * TODO: test or remove
 */
class RecordLengthManipulation(private val recordLengthModifier: Double, private val messageType: ProtocolMessageType) :
    TlsManipulation() {

    override val name: String
        get() = "record_length(recordLengthModifier=$recordLengthModifier, messageType=$messageType)"

    override fun afterRecordCreation(record: Record) {
        val incorrectRecordLengthModification = IntegerMultiplyWithMaximumModification(recordLengthModifier, ManipulationConstants.TLS_MAX_RECORD_SIZE_CORRECT)

        if (record.contentMessageType == messageType){
            record.length = ModifiableVariableFactory.createIntegerModifiableVariable()
            record.length.modification = incorrectRecordLengthModification
        }
    }
}