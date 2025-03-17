package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.GARBAGE_BYTE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_OFFSET_FOR_TOTAL_SIZE
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage

/**
 * Adds a padding extension and pads the message to maximum record size later
 */
class PaddingExtensionManipulation(val padToSize: Int) : TlsManipulation() {
    override fun afterConfigInit(tlsConfig: Config) {
        tlsConfig.isAddPaddingExtension = true
    }

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only add padding extension in ClientHello messages, skipping")
            return
        }

        val paddingExtension = message.getExtension(PaddingExtensionMessage::class.java)
        // needs to be original value because of potential other manipulations that specifically decrease the size
        val bytesToAdd = padToSize - message.length.originalValue - MESSAGE_OFFSET_FOR_TOTAL_SIZE
        if (bytesToAdd <= 0) {
            throw NotConnectableException(
                ConnectionReturn.ALREADY_DEFAULT,
                "Message length is already longer than desired size. No padding applied!"
            )
        }

        // change extension length to correct size
        val explicitModification = IntegerExplicitValueModification()
        explicitModification.explicitValue = paddingExtension.extensionLength.value + bytesToAdd
        paddingExtension.extensionLength.modification = explicitModification

        // add correct number of extension bytes
        val explicitByteArrayModification = ByteArrayExplicitValueModification()
        explicitByteArrayModification.explicitValue = paddingExtension.paddingBytes.value + ByteArray(bytesToAdd).also { it.fill(GARBAGE_BYTE) }
        paddingExtension.paddingBytes.modification = explicitByteArrayModification
    }

    override val name: String
        get() = "padding_extension(padToSize=$padToSize)"
}