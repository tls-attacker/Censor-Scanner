package de.rub.nds.censor.core.connection.manipulation.tls.extension.length

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.util.Util.getParsedExtensionsUntilFirstSni
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage

/**
 * Sets the extensions length to reach until the end of the first entry in the SNI list (possibly modified SNI)
 */
class ExtensionsLengthOnlyFirstSniEntryManipulation : TlsManipulation() {
    override val name: String
        get() = "extensions_length(only_first)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only set extensions length to SNI-dependant value in ClientHello messages, skipping")
            return
        }

        val explicitModification = IntegerExplicitValueModification()
        try {
            explicitModification.explicitValue =
                message.getParsedExtensionsUntilFirstSni() +
                        tlsConfig.defaultSniHostnames[0].serverName.value.size +
                        SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
            if (explicitModification.explicitValue == message.extensionsLength.value) {
                throw NotConnectableException(
                    ConnectionReturn.ALREADY_DEFAULT,
                    "Extensions length is already correct for only first ${explicitModification.explicitValue}"
                )
            }
            message.extensionsLength.modification = explicitModification
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