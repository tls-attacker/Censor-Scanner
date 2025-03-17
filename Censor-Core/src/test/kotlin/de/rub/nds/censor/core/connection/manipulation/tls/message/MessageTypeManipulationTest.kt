package de.rub.nds.censor.core.connection.manipulation.tls.message

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage

class MessageTypeManipulationTest: ManipulationTest<MessageTypeManipulation>(fails = true) {

    override fun targetManipulations(): Collection<MessageTypeManipulation> {
        return listOf(
            MessageTypeManipulation(0x00, ServerHelloMessage::class.java),
            MessageTypeManipulation(0x01, ClientHelloMessage::class.java),
            MessageTypeManipulation(0x00, ClientHelloMessage::class.java),
            MessageTypeManipulation(0x7f, ClientHelloMessage::class.java),
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: MessageTypeManipulation,
        exception: Exception?
    ) {
        if (manipulation.messageType == ServerHelloMessage::class.java) {
            // everything works and no changes made to clienthello version
            assert(connection.getRecord().protocolMessageBytes.value[0] == (0x01).toByte()
            )
        } else if (manipulation.newType == (0x01).toByte()) {
            // already default
            assert((exception as NotConnectableException).reason == ConnectionReturn.ALREADY_DEFAULT)
        } else {
            assert(connection.getRecord().protocolMessageBytes.value[0] == manipulation.newType)
        }
    }
}