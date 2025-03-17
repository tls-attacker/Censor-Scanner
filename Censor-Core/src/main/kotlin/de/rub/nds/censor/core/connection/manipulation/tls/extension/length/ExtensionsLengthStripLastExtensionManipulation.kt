package de.rub.nds.censor.core.connection.manipulation.tls.extension.length

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.util.Util.getParsedExtensionsLengthWithoutLast
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage

/**
 * Modifies the extensions length to exclude the last extension
 */
class ExtensionsLengthStripLastExtensionManipulation : TlsManipulation() {
    override val name: String
        get() = "extensions_length(strip_last)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only strip extension of ClientHello messages, skipping")
            return
        }

        val explicitModification = IntegerExplicitValueModification()
        explicitModification.explicitValue = message.getParsedExtensionsLengthWithoutLast().coerceAtMost(MAXIMUM_2_BYTE_FIELD_VALUE)
        if (explicitModification.explicitValue == message.extensionsLength.value) {
            throw NotConnectableException(
                ConnectionReturn.ALREADY_DEFAULT,
                "Extensions length is already correct for strip last ${explicitModification.explicitValue}"
            )
        }
        message.extensionsLength.modification = explicitModification
    }
}