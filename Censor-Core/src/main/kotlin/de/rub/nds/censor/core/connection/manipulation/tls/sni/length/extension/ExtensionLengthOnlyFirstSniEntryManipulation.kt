package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.extension

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage

/**
 * Sets the extension length to be after the first element in the SNI list
 */
class ExtensionLengthOnlyFirstSniEntryManipulation : TlsManipulation() {
    override val name: String
        get() = "sni_ext_length(only_first)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only set extension length length in ClientHello messages, skipping")
            return
        }

        val sni = message.getExtension(ServerNameIndicationExtensionMessage::class.java)
        val explicitModification = IntegerExplicitValueModification()

        try {
            explicitModification.explicitValue = tlsConfig.defaultSniHostnames[0].serverName.value.size + SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
            if (explicitModification.explicitValue == sni.extensionLength.value) {
                throw NotConnectableException(
                    ConnectionReturn.ALREADY_DEFAULT,
                    "Extension length is already correct for only first ${explicitModification.explicitValue}"
                )
            }
            sni.extensionLength.modification = explicitModification
        } catch (e: IndexOutOfBoundsException) {
            throw NotConnectableException(
                ConnectionReturn.INAPPLICABLE,
                "SNI is missing because of other modifications"
            )
        }
    }
}