package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.censor.core.constants.RecordManipulationType
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import org.junit.jupiter.api.Assertions
import java.lang.Exception

class RecordInjectionManipulationTest: ManipulationTest<RecordInjectionManipulation>(fails = true, longWait = true) { // fails = true necessary because of recordTypeBefore = RecordManipulationType.HANDSHAKE_NULL_BYTE
    override fun targetManipulations(): Collection<RecordInjectionManipulation> {
        return listOf(
            RecordInjectionManipulation(),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.INVALID_TYPE),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.INVALID_TYPE),
            // TODO: reimplement, for SOME reason fails in tls-attacker receive even tho messages are sent correctly
            // RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.CHANGE_CIPHER_SPEC_VALID),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.CHANGE_CIPHER_SPEC_VALID),
            // TODO: reimplement, for SOME reason fails in tls-attacker receive even tho messages are sent correctly
            // RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.ALERT_INCOMPLETE),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.ALERT_INCOMPLETE),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.ALERT_INTERNAL_WARN),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.ALERT_INTERNAL_WARN),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.ALERT_INTERNAL_FATAL),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.ALERT_INTERNAL_FATAL),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.HANDSHAKE_NULL_BYTE),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.HANDSHAKE_NULL_BYTE),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.APPLICATION_DATA_NULL_BYTE),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.APPLICATION_DATA_NULL_BYTE),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.HEARTBEAT_REQUEST),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.HEARTBEAT_REQUEST),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.HEARTBEAT_RESPONSE),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.HEARTBEAT_RESPONSE),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.HEARTBEAT_INCOMPLETE),
            RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.HEARTBEAT_INCOMPLETE),
            RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.ALERT_INTERNAL_WARN, recordTypeAfter = RecordManipulationType.HEARTBEAT_REQUEST)
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: RecordInjectionManipulation,
        exception: Exception?
    ) {
        val records = connection.state.workflowTrace.lastReceivingAction.receivedRecords
        var expectedRecords = 1
        if (manipulation.recordTypeBefore != null) expectedRecords += 1
        if (manipulation.recordTypeAfter != null) expectedRecords += 1
        Assertions.assertEquals(expectedRecords, records.size) // correct number of records

        // check if correct content types for all records
        records.forEachIndexed { index, record ->
            if (manipulation.recordTypeBefore != null && index == 0) {
                Assertions.assertEquals(manipulation.recordTypeBefore!!.protocolType.value, record.contentType.value)
            } else if (manipulation.recordTypeAfter != null && index == records.size - 1) {
                Assertions.assertEquals(manipulation.recordTypeAfter!!.protocolType.value, record.contentType.value)
            } else {
                Assertions.assertEquals(ProtocolMessageType.HANDSHAKE.value, record.contentType.value)
            }
        }
    }
}