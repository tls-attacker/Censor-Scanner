package de.rub.nds.censor.core.connection.manipulation.tls.extension.length

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_FIELD_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSIONS_LENGTH_LENGTH
import de.rub.nds.censor.core.util.Util.toHexString

class ExtensionsLengthManipulationTest: SniTest<ExtensionsLengthManipulation>(fails = true) {
    override fun targetManipulations(): Collection<ExtensionsLengthManipulation> {
        return listOf(
            ExtensionsLengthManipulation(0.0),
            ExtensionsLengthManipulation(0.5),
            ExtensionsLengthManipulation(2.0),
            ExtensionsLengthManipulation(1.0E34)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ExtensionsLengthManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // message length unchanged
        val correctMessageLength = (defaultMessageLength).toHexString(MESSAGE_LENGTH_SIZE)
        val correctRecordLength = (defaultMessageLength+4).toHexString(MESSAGE_LENGTH_FIELD_LENGTH)
        assert(actual.contains("0303" + correctRecordLength + "01" + correctMessageLength + "0303", ignoreCase = true))

        // correct changes to extensions length
        val expectedExtensionsSize = (defaultExtensionsLength * manipulation.extensionsLengthModifier).toInt().toHexString(TLS_EXTENSIONS_LENGTH_LENGTH)
        val expectedSni = "00000100" + expectedExtensionsSize + "000b000201"
        assert(actual.contains(expectedSni, ignoreCase = true))
    }
}