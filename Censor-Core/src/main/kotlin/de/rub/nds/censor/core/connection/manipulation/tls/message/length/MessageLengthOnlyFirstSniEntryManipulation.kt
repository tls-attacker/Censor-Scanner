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
 * Sets the message length to reach until the end of the first entry in the SNI list (possibly modified SNI)
 */
class MessageLengthOnlyFirstSniEntryManipulation : TlsManipulation()  {
    override val name: String
        get() = "message_length(only_first)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only set message length to SNI-dependant value in ClientHello messages, skipping")
            return
        }

        val explicitModification = IntegerExplicitValueModification()
        try {
            explicitModification.explicitValue =
                message.getParsedExtensionsUntilFirstSni() +
                        tlsConfig.defaultSniHostnames[0].serverName.value.size +
                        SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH +
                        MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN
            if (explicitModification.explicitValue == message.length.value) {
                throw NotConnectableException(
                    ConnectionReturn.ALREADY_DEFAULT,
                    "Message length is already correct for only first ${explicitModification.explicitValue}"
                )
            }
            message.length.modification = explicitModification
        } catch (e: IndexOutOfBoundsException) {
            throw NotConnectableException(
                ConnectionReturn.INAPPLICABLE,
                "SNI is missing because of other modifications"
            )
        } catch (e: IllegalArgumentException) {
            // no sni present
            throw NotConnectableException(ConnectionReturn.INAPPLICABLE, "No SNI present")
        }
    }
}