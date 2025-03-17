package de.rub.nds.censor.core.connection.manipulation.tls.extension.length

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.GARBAGE_BYTE
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage

/**
 * Adds the given number to the length of the extensions and then adds garbage bytes
 */
class ExtensionsLengthTooLongGarbageManipulation(val garbageCount: Int) : TlsManipulation() {
    override val name: String
        get() = "extensions_length(too_long_garbage)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only set extensions length in ClientHello messages, skipping")
            return
        }

        // add BYTE_LENGTH to length
        val explicitModification = IntegerExplicitValueModification()
        explicitModification.explicitValue = (message.extensionsLength.value + garbageCount).coerceAtMost(MAXIMUM_2_BYTE_FIELD_VALUE)
        message.extensionsLength.modification = explicitModification

        // add BYTE_LENGTH garbage bytes
        val explicitByteModification = ByteArrayExplicitValueModification()
        explicitByteModification.explicitValue = message.extensionBytes.value + ByteArray(garbageCount).also { it.fill(GARBAGE_BYTE) }
        message.extensionBytes.modification = explicitByteModification
    }
}