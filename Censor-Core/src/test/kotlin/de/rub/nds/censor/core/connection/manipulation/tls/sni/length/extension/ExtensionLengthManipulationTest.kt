package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.extension

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import java.lang.Exception

class ExtensionLengthManipulationTest: SniTest<ExtensionLengthManipulation>(fails = true) {
    override fun targetManipulations(): Collection<ExtensionLengthManipulation> {
        return listOf(
            ExtensionLengthManipulation(0.0),
            ExtensionLengthManipulation(0.5),
            ExtensionLengthManipulation(2.0),
            ExtensionLengthManipulation(1.0E34)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ExtensionLengthManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()
        val expectedSize = when(manipulation.extensionLengthModifier) {
            0.0 -> {
                "0000"
            }
            0.5 -> {
                "0008"
            }
            2.0 -> {
                "0020"
            }
            1.0E34 -> {
                "ffff"
            }
            else -> {
                throw Exception()
            }
        }
        val expectedSni = "0000" + expectedSize + "000e00000b6578616d706c652e636f6d"
        assert(actual.contains(expectedSni, ignoreCase = true))
    }
}