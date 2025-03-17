package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import java.lang.Exception

class ListLengthManipulationTest: SniTest<ListLengthManipulation>(fails = true) {
    override fun targetManipulations(): Collection<ListLengthManipulation> {
        return listOf(
            ListLengthManipulation(0.0),
            ListLengthManipulation(0.5),
            ListLengthManipulation(2.0),
            ListLengthManipulation(1.0E34),
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ListLengthManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()
        val expectedSize = when(manipulation.listLengthModifier) {
            0.0 -> {
                "0000"
            }
            0.5 -> {
                "0007"
            }
            2.0 -> {
                "001c"
            }
            1.0E34 -> {
                "ffff"
            }
            else -> {
                throw Exception()
            }
        }
        val expectedSni = "00000010" + expectedSize + "00000b6578616d706c652e636f6d"
        assert(actual.contains(expectedSni, ignoreCase = true))
    }
}