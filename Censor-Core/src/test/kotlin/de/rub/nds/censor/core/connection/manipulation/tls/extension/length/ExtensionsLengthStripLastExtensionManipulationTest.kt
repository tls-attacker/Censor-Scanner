package de.rub.nds.censor.core.connection.manipulation.tls.extension.length

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants
import de.rub.nds.censor.core.constants.ManipulationConstants.HANDSHAKE_TYPE_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.RECORD_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSIONS_LENGTH_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSION_HEADER
import de.rub.nds.censor.core.util.Util.toHexString

class ExtensionsLengthStripLastExtensionManipulationTest: SniTest<ExtensionsLengthStripLastExtensionManipulation>(fails = true) {
    override fun targetManipulations(): Collection<ExtensionsLengthStripLastExtensionManipulation> {
        return listOf(
            ExtensionsLengthStripLastExtensionManipulation()
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ExtensionsLengthStripLastExtensionManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // check correct modification and all super lengths remain the same after manipulations
        val correctMessageLength = (defaultMessageLength).toHexString(MESSAGE_LENGTH_SIZE)
        val correctRecordLength = (defaultMessageLength + MESSAGE_LENGTH_SIZE + HANDSHAKE_TYPE_SIZE).toHexString(
            RECORD_LENGTH_SIZE
        )
        val correctExtensionsLength = (defaultEcPointFormatsExtensionLength + defaultSupportedGroupsExtensionLength +
                defaultSniExtensionLength + defaultSignatureAlgorithmExtensionLength + 4 * TLS_EXTENSION_HEADER).toHexString(TLS_EXTENSIONS_LENGTH_LENGTH)

        assert(actual.contains("160303" + correctRecordLength + "01" + correctMessageLength + "0303", ignoreCase = true))
        assert(actual.contains("00000100" + correctExtensionsLength + "000b00", ignoreCase = true))
    }
}