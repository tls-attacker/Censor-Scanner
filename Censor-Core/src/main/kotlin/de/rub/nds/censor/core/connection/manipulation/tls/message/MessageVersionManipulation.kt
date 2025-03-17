package de.rub.nds.censor.core.connection.manipulation.tls.message

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.HelloMessage

/**
 * Modifies the version of the given message type in the workflowtrace
 */
class MessageVersionManipulation(val newVersion: ByteArray, val messageType: Class<out HelloMessage>): TlsManipulation() {

    override val name: String
        get() = "message_version(newVersion=$newVersion, messageType=$messageType)"

    init {
        require(newVersion.size == 2) { "Extension type must be 2 bytes long" }
    }

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (messageType.isInstance(message)) {
            val castedMessage = message as HelloMessage
            if (castedMessage.protocolVersion.value.contentEquals(newVersion)) {
                throw NotConnectableException(ConnectionReturn.ALREADY_DEFAULT, "Message version is already $newVersion")
            } else {
                val explicitModification = ByteArrayExplicitValueModification()
                explicitModification.explicitValue = newVersion
                castedMessage.protocolVersion.modification = explicitModification
            }
        }
    }
}