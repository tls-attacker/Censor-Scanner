package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import org.junit.jupiter.api.Test
import java.lang.AssertionError

class RecordVersionManipulationTest: ManipulationTest<RecordVersionManipulation>(fails = true) {

    @Test
    override fun initializeExceptionsTest() {
        try {
            RecordVersionManipulation(byteArrayOf(0x00, 0x00, 0x00, 0x00), ProtocolMessageType.UNKNOWN)
            throw AssertionError("Initialization of RecordVersion did not fail with too many bytes.")
        } catch (_: IllegalArgumentException) {

        }
        try {
            RecordVersionManipulation(byteArrayOf(), ProtocolMessageType.UNKNOWN)
            throw AssertionError("Initialization of RecordVersion did not fail with too few bytes.")
        } catch (_: IllegalArgumentException) {

        }
    }

    override fun targetManipulations(): Collection<RecordVersionManipulation> {
        return listOf(
            RecordVersionManipulation(byteArrayOf(0x00, 0x00), ProtocolMessageType.APPLICATION_DATA),
            RecordVersionManipulation(byteArrayOf(0x03, 0x03), ProtocolMessageType.HANDSHAKE),
            RecordVersionManipulation(byteArrayOf(0x03, 0x01), ProtocolMessageType.HANDSHAKE),
            RecordVersionManipulation(byteArrayOf(-1, -1), ProtocolMessageType.HANDSHAKE))
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: RecordVersionManipulation,
        exception: Exception?
    ) {
        if (manipulation.messageType == ProtocolMessageType.APPLICATION_DATA) {
            // everything works and no changes made to clienthello version
            assert(connection.getRecord().completeRecordBytes.value.copyOfRange(1,3).contentEquals(
                byteArrayOf(0x03, 0x03))
            )
        } else if (manipulation.newProtocolVersion.contentEquals(byteArrayOf(0x03, 0x03))) {
            // already default
            assert((exception as NotConnectableException).reason == ConnectionReturn.ALREADY_DEFAULT)
        } else {
            assert(connection.getRecord().completeRecordBytes.value.copyOfRange(1,3).contentEquals(manipulation.newProtocolVersion))
        }
    }
}