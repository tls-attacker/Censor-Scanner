package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.modifiablevariable.singlebyte.ByteExplicitValueModification
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import de.rub.nds.tlsattacker.core.record.Record

/**
 * Manipulation that modifies the content type of TLS records with a given content type. e.g. this manipulation
 * could change all handshake records to ChangeCipherSpec records.
 */
class RecordContentTypeManipulation(val newContentType: ProtocolMessageType, val oldContentType: ProtocolMessageType): TlsManipulation() {
    override val name: String
        get() = "record_content_type(contentType=$newContentType, messageType=$oldContentType)"

    init {
        require(newContentType != oldContentType)
    }

    override fun afterRecordCreation(record: Record) {
        val incorrectContentType = ModifiableByte()
        val incorrectContentTypeModification = ByteExplicitValueModification()
        incorrectContentTypeModification.explicitValue = newContentType.value

        if (record.contentMessageType == oldContentType){
            record.contentType = incorrectContentType
            record.contentType.modification = incorrectContentTypeModification
        }
    }
}