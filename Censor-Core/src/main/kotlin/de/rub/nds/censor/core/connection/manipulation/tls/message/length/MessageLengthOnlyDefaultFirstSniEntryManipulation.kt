package de.rub.nds.censor.core.connection.manipulation.tls.message.length

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.util.Util.getParsedExtensionsUntilFirstSni
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage

/**
 * Sets the message length to its default value (without SNI modifications)
 */
class MessageLengthOnlyDefaultFirstSniEntryManipulation(private val correctHostname: String) : TlsManipulation() {
    override val name: String
        get() = "message_length(default)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only set message length to SNI-dependant value in ClientHello messages, skipping")
            return
        }

        val explicitModification = IntegerExplicitValueModification()
        try {
            explicitModification.explicitValue =
                message.getParsedExtensionsUntilFirstSni()+
                    correctHostname.length +
                    SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH +
                    MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN

        } catch (e: IllegalArgumentException) {
            // no sni present
            throw NotConnectableException(ConnectionReturn.INAPPLICABLE, "No SNI present")
        }

        if (explicitModification.explicitValue == message.length.value) {
            throw NotConnectableException(
                ConnectionReturn.ALREADY_DEFAULT,
                "Message length is already correct for default ${explicitModification.explicitValue}"
            )
        }
        message.length.modification = explicitModification
    }
}