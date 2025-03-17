package de.rub.nds.censor.core.connection.manipulation.tls.message.length

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.GARBAGE_BYTE
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage

/**
 * Adds the given number to the length of the message and then adds garbage bytes
 */
class MessageLengthTooLongGarbageManipulation(val garbageCount: Int, private val messageType: Class<out HandshakeMessage>) : TlsManipulation() {
    override val name: String
        get() = "message_length(too_long_garbage)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (!messageType.isInstance(message)) {
            return
        } else {
            message as HandshakeMessage
        }

        // add BYTE_LENGTH to length
        val explicitModification = IntegerExplicitValueModification()
        explicitModification.explicitValue = (message.length.value + garbageCount).coerceAtMost(MAXIMUM_2_BYTE_FIELD_VALUE)
        message.length.modification = explicitModification

        // add BYTE_LENGTH garbage bytes
        val explicitByteModification = ByteArrayExplicitValueModification()
        explicitByteModification.explicitValue = message.messageContent.value + ByteArray(garbageCount).also { it.fill(GARBAGE_BYTE) }
        message.messageContent.modification = explicitByteModification
    }
}