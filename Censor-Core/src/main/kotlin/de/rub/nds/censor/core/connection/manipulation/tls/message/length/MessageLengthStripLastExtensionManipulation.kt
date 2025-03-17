package de.rub.nds.censor.core.connection.manipulation.tls.message.length

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.util.Util.getParsedExtensionsLengthWithoutLast
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage

/**
 * Modifies the message length to exclude the last extension
 */
class MessageLengthStripLastExtensionManipulation : TlsManipulation() {
    override val name: String
        get() = "message_length(strip_last)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only strip extension of ClientHello messages, skipping")
            return
        }

        val explicitModification = IntegerExplicitValueModification()
        explicitModification.explicitValue = message.getParsedExtensionsLengthWithoutLast() + MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN
        if (explicitModification.explicitValue == message.length.value) {
            throw NotConnectableException(
                ConnectionReturn.ALREADY_DEFAULT,
                "Message length is already correct for strip last ${explicitModification.explicitValue}"
            )
        }
        message.length.modification = explicitModification
    }
}