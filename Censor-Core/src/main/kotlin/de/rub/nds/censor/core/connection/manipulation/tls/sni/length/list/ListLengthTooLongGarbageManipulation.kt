package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.GARBAGE_BYTE
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage

class ListLengthTooLongGarbageManipulation(val garbageCount: Int) : TlsManipulation() {
    override val name: String
        get() = "sni_list_length(too_long_garbage)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only set SNI list length in ClientHello messages, skipping")
            return
        }

        val sni = message.getExtension(ServerNameIndicationExtensionMessage::class.java)

        // add BYTE_LENGTH to length
        val explicitModification = IntegerExplicitValueModification()
        explicitModification.explicitValue = (sni.serverNameListLength.value + garbageCount).coerceAtMost(MAXIMUM_2_BYTE_FIELD_VALUE)
        sni.serverNameListLength.modification = explicitModification

        // add BYTE_LENGTH garbage bytes
        val explicitByteModification = ByteArrayExplicitValueModification()
        explicitByteModification.explicitValue = sni.serverNameListBytes.value + ByteArray(garbageCount).also { it.fill(GARBAGE_BYTE) }
        sni.serverNameListBytes.modification = explicitByteModification
    }
}