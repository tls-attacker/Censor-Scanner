package de.rub.nds.censor.core.connection.manipulation.tls.message

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.modifiablevariable.singlebyte.ByteExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage

/**
 * Modifies the type of the given message type in the workflowtrace.
 */
class MessageTypeManipulation(val newType: Byte, val messageType: Class<out HelloMessage>): TlsManipulation() {
    override val name: String
        get() = "message_type(newVersion=$newType, messageType=$messageType)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (messageType.isInstance(message)) {
            val castedMessage = message as HelloMessage
            if (castedMessage.type.value.equals(newType)) {
                throw NotConnectableException(ConnectionReturn.ALREADY_DEFAULT, "Message Type is already $newType")
            } else {
                val explicitModification = ByteExplicitValueModification()
                explicitModification.explicitValue = newType
                castedMessage.type.modification = explicitModification
            }
        }
    }
}