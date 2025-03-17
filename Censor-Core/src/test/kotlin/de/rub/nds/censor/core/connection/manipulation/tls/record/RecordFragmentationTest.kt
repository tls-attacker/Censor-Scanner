package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_TO_OUTER
import de.rub.nds.censor.core.constants.RecordManipulationType
import de.rub.nds.censor.core.util.Util.getParsedExtensionsUntilFirstSni
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import org.junit.jupiter.api.Assertions
import java.lang.Exception

class RecordFragmentationTest : ManipulationTest<RecordFragmentationManipulation>(fails = true) {

    private val hostname = "example.com"

    // needs SNI for point selection
    override fun extraManipulations(): Collection<TlsManipulation> {
        return listOf(SniExtensionManipulation(hostname, true))
    }
    override fun targetManipulations(): Collection<RecordFragmentationManipulation> {
        return listOf(
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_MESSAGE_HEADER),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.INVALID_TYPE),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.INVALID_TYPE),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.INVALID_TYPE),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.CHANGE_CIPHER_SPEC_VALID),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.CHANGE_CIPHER_SPEC_VALID),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.CHANGE_CIPHER_SPEC_VALID),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.ALERT_INCOMPLETE),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.ALERT_INCOMPLETE),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.ALERT_INCOMPLETE),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.ALERT_INTERNAL_WARN),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.ALERT_INTERNAL_WARN),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.ALERT_INTERNAL_WARN),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.ALERT_INTERNAL_FATAL),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.ALERT_INTERNAL_FATAL),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.ALERT_INTERNAL_FATAL),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.HANDSHAKE_NULL_BYTE),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.HANDSHAKE_NULL_BYTE),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.HANDSHAKE_NULL_BYTE),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.APPLICATION_DATA_NULL_BYTE),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.APPLICATION_DATA_NULL_BYTE),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.APPLICATION_DATA_NULL_BYTE),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.HEARTBEAT_REQUEST),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.HEARTBEAT_REQUEST),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.HEARTBEAT_REQUEST),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.HEARTBEAT_RESPONSE),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.HEARTBEAT_RESPONSE),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.HEARTBEAT_RESPONSE),
            RecordFragmentationManipulation(RecordFragmentationPoint.BEFORE_SNI, RecordManipulationType.HEARTBEAT_INCOMPLETE),
            RecordFragmentationManipulation(RecordFragmentationPoint.IN_HOSTNAME, RecordManipulationType.HEARTBEAT_INCOMPLETE),
            RecordFragmentationManipulation(RecordFragmentationPoint.AFTER_SNI, RecordManipulationType.HEARTBEAT_INCOMPLETE),
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: RecordFragmentationManipulation,
        exception: Exception?
    ) {
        // we expect 2 records without injection, else 3
        val records = connection.state.workflowTrace.lastReceivingAction.receivedRecords
        if (manipulation.protocolMessageTypeToInject != null) {
            assert(records.size == 3)
        } else {
            assert(records.size == 2)
        }

        // make sure the records are split correctly according to selected point
        val message = connection.state.workflowTrace.lastReceivingAction.receivedMessages[0]
        if (message is CoreClientHelloMessage){
            val actualRecordSize = records[0].length.value

            val sni = message.getExtension(ServerNameIndicationExtensionMessage::class.java)
            val lengthUntilSni = message.getLength().value + MESSAGE_LENGTH_TO_OUTER - message.getExtensionsLength().value +  message.getParsedExtensionsUntilFirstSni()
            val expectedRecordSize = when (manipulation.recordFragmentationPoint) {
                RecordFragmentationPoint.IN_MESSAGE_HEADER -> 2
                RecordFragmentationPoint.BEFORE_SNI -> lengthUntilSni
                RecordFragmentationPoint.IN_HOSTNAME -> lengthUntilSni + (sni.serverNameList[0].serverName.value.size/2) + ManipulationConstants.SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH + ManipulationConstants.TLS_EXTENSION_HEADER
                RecordFragmentationPoint.AFTER_SNI -> lengthUntilSni + sni.extensionLength.value + ManipulationConstants.TLS_EXTENSION_HEADER
            }
            Assertions.assertEquals(expectedRecordSize, actualRecordSize)
        }

        // check if correct content types for all records
        records.forEachIndexed { index, record ->
            if (index == 0) {
                Assertions.assertEquals(ProtocolMessageType.HANDSHAKE.value, record.contentType.value)
            } else if (index == records.size - 1) {
                Assertions.assertEquals(ProtocolMessageType.HANDSHAKE.value, record.contentType.value)
            } else if (manipulation.protocolMessageTypeToInject != null){ // injected record in between
                Assertions.assertEquals(manipulation.protocolMessageTypeToInject!!.protocolType.value, record.contentType.value)
            }
        }
    }
}