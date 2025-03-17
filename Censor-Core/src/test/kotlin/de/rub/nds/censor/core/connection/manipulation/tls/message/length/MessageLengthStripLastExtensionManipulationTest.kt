package de.rub.nds.censor.core.connection.manipulation.tls.message.length

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants.HANDSHAKE_TYPE_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_FIELD_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.STRIPPED_EXTENSION_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSION_HEADER
import de.rub.nds.censor.core.util.Util.toHexString

class MessageLengthStripLastExtensionManipulationTest: SniTest<MessageLengthStripLastExtensionManipulation>(fails = true) {
    override fun targetManipulations(): Collection<MessageLengthStripLastExtensionManipulation> {
        return listOf(
            MessageLengthStripLastExtensionManipulation()
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: MessageLengthStripLastExtensionManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // check correct modification and all super lengths remain the same after manipulations
        val correctExtensionsLength = defaultEcPointFormatsExtensionLength + defaultSupportedGroupsExtensionLength +
                defaultSniExtensionLength + defaultSignatureAlgorithmExtensionLength + 4 * TLS_EXTENSION_HEADER
        val correctMessageLength = (MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN + correctExtensionsLength).toHexString(MESSAGE_LENGTH_SIZE)
        val correctRecordLength = (MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN + correctExtensionsLength + STRIPPED_EXTENSION_LENGTH + MESSAGE_LENGTH_SIZE + HANDSHAKE_TYPE_SIZE).toHexString(
            MESSAGE_LENGTH_FIELD_LENGTH)

        assert(actual.contains("160303" + correctRecordLength + "01" + correctMessageLength + "0303", ignoreCase = true))
    }
}