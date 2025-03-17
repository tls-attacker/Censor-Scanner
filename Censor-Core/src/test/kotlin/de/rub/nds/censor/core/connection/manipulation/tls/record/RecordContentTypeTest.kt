package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import org.junit.jupiter.api.Assertions.assertEquals

class RecordContentTypeTest: ManipulationTest<RecordContentTypeManipulation>(fails = true) {

    override fun initializeExceptionsTest() {
        try {
            RecordContentTypeManipulation(ProtocolMessageType.HANDSHAKE, ProtocolMessageType.HANDSHAKE)
            throw AssertionError("Manipulation is initializable with two identical ProtocolVersions")
        } catch (_ : IllegalArgumentException) {

        }
        try {
            RecordContentTypeManipulation(ProtocolMessageType.ALERT, ProtocolMessageType.ALERT)
            throw AssertionError("Manipulation is initializable with two identical ProtocolVersions")
        } catch (_ : IllegalArgumentException) {

        }
    }

    override fun targetManipulations(): Collection<RecordContentTypeManipulation> {
        return listOf(
            RecordContentTypeManipulation(ProtocolMessageType.UNKNOWN, ProtocolMessageType.HANDSHAKE),
            RecordContentTypeManipulation(ProtocolMessageType.ALERT, ProtocolMessageType.HANDSHAKE),
            RecordContentTypeManipulation(ProtocolMessageType.APPLICATION_DATA, ProtocolMessageType.HANDSHAKE),
            RecordContentTypeManipulation(ProtocolMessageType.HEARTBEAT, ProtocolMessageType.HANDSHAKE),
            RecordContentTypeManipulation(ProtocolMessageType.TLS12_CID, ProtocolMessageType.CHANGE_CIPHER_SPEC),
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: RecordContentTypeManipulation,
        exception: Exception?
    ) {
        val expected = if(manipulation.oldContentType == ProtocolMessageType.HANDSHAKE) {
            manipulation.newContentType.value
        } else {
            ProtocolMessageType.HANDSHAKE.value
        }
        val actual = connection.getRecord().contentType.value
        assertEquals(expected, actual)
    }
}