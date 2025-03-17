package de.rub.nds.censor.core.connection.manipulation.tls

import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_OFFSET_FOR_TOTAL_SIZE
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage

/**
 * Adds cipher suites as padding
 */
class AddCipherSuitesAsPaddingManipulation(val padToSize: Int) : TlsManipulation() {

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only add cipher suites in ClientHello messages, skipping")
            return
        }

        // needs to be original value because of potential other manipulations that specifically decrease the size
        var bytesToAdd = padToSize - message.length.originalValue - MESSAGE_OFFSET_FOR_TOTAL_SIZE
        if (bytesToAdd % 2 == 1) {
            bytesToAdd -= 1
        }
        if (bytesToAdd <= 0) {
            throw NotConnectableException(
                ConnectionReturn.ALREADY_DEFAULT,
                "Message length is already longer than desired size. No padding applied!"
            )
        }

        // change length to correct size
        val explicitModification = IntegerExplicitValueModification()
        explicitModification.explicitValue = message.cipherSuiteLength.value + bytesToAdd
        message.cipherSuiteLength.modification = explicitModification

        // add correct number of cipher suites
        val explicitByteArrayModification = ByteArrayExplicitValueModification()
        explicitByteArrayModification.explicitValue = message.cipherSuites.value + ByteArray(bytesToAdd).also { it.fill(0x00) } // TLS_NULL_WITH_NULL_NULL suite
        message.cipherSuites.modification = explicitByteArrayModification
    }

    override val name: String
        get() = "cipher_suites_padding(padToSize=$padToSize)"
}