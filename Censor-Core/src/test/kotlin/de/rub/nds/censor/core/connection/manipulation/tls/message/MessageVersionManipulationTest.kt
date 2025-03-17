package de.rub.nds.censor.core.connection.manipulation.tls.message

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage
import org.junit.jupiter.api.Test
import java.lang.AssertionError

class MessageVersionManipulationTest: ManipulationTest<MessageVersionManipulation>(fails = true) {

    @Test
    override fun initializeExceptionsTest() {
        try {
            MessageVersionManipulation(byteArrayOf(0x00, 0x00, 0x00, 0x00), ClientHelloMessage::class.java)
            throw AssertionError("Initialization of MessageVersion did not fail with too many bytes.")
        } catch (_: IllegalArgumentException) {

        }
        try {
            MessageVersionManipulation(byteArrayOf(), ClientHelloMessage::class.java)
            throw AssertionError("Initialization of MessageVersion did not fail with too few bytes.")
        } catch (_: IllegalArgumentException) {

        }
    }

    override fun targetManipulations(): Collection<MessageVersionManipulation> {
        return listOf(
            MessageVersionManipulation(byteArrayOf(0x03, 0x10), ServerHelloMessage::class.java),
            MessageVersionManipulation(byteArrayOf(0x03, 0x03), ClientHelloMessage::class.java),
            MessageVersionManipulation(byteArrayOf(0x03, 0x02), ClientHelloMessage::class.java),
            MessageVersionManipulation(byteArrayOf(-1, -1), ClientHelloMessage::class.java),
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: MessageVersionManipulation,
        exception: Exception?
    ) {
        if (manipulation.messageType == ServerHelloMessage::class.java) {
            // everything works and no changes made to clienthello version
            assert(connection.getRecord().protocolMessageBytes.value.copyOfRange(4,6).contentEquals(
                byteArrayOf(0x03, 0x03))
            )
        } else if (manipulation.newVersion.contentEquals(byteArrayOf(0x03, 0x03))) {
            // already default
            assert((exception as NotConnectableException).reason == ConnectionReturn.ALREADY_DEFAULT)
        } else {
            assert(connection.getRecord().protocolMessageBytes.value.copyOfRange(4,6).contentEquals(manipulation.newVersion))
        }
    }
}