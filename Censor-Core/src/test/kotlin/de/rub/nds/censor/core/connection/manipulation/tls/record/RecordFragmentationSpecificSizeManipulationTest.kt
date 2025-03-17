package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import org.junit.jupiter.api.Assertions.assertEquals
import java.lang.Exception

class RecordFragmentationSpecificSizeManipulationTest : ManipulationTest<RecordFragmentationSpecificSizeManipulation>() {
    override fun targetManipulations(): Collection<RecordFragmentationSpecificSizeManipulation> {
        return listOf(
            RecordFragmentationSpecificSizeManipulation(500),
            RecordFragmentationSpecificSizeManipulation(10),
            RecordFragmentationSpecificSizeManipulation(42)
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: RecordFragmentationSpecificSizeManipulation,
        exception: Exception?
    ) {
        // we expect two records, the first one with a size of 500 bytes
        val records = connection.state.workflowTrace.lastReceivingAction.receivedRecords
        assert(records.size == 2)
        val actualRecordSize = records[0].length.value
        val expectedRecordSize = manipulation.recordSize
        assertEquals(expectedRecordSize, actualRecordSize)
    }
}