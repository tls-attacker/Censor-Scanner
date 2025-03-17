package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import de.rub.nds.tlsattacker.core.record.Record

/**
 * Manipulation for modifying the protocol version contained in all TLS records with the given message Type. E.g. this
 * manipulation could change the Protocol version for all TLS records that contain a TLS alert.
 */
class RecordVersionManipulation(val newProtocolVersion: ByteArray, val messageType: ProtocolMessageType): TlsManipulation() {
    override val name: String
        get() = "record_version(protocolVersion=${newProtocolVersion.decodeToString()}, messageType=$messageType)"

    init {
        require(newProtocolVersion.size == 2)
    }

    override fun afterRecordCreation(record: Record) {
        val incorrectRecordVersion = ModifiableByteArray()
        val incorrectRecordVersionModification = ByteArrayExplicitValueModification()
        incorrectRecordVersionModification.explicitValue = newProtocolVersion
        incorrectRecordVersion.modification = incorrectRecordVersionModification

        if (record.contentMessageType == messageType){
            if (record.protocolVersion.value.contentEquals(newProtocolVersion)) {
                throw NotConnectableException(ConnectionReturn.ALREADY_DEFAULT, "Record version is already $newProtocolVersion")
            } else {
                record.protocolVersion = incorrectRecordVersion
            }
        }
    }
}