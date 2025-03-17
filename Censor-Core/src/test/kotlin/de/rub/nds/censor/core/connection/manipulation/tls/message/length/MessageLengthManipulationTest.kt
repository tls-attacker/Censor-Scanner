package de.rub.nds.censor.core.connection.manipulation.tls.message.length

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_FIELD_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_VERSION_FIELD_LENGTH
import de.rub.nds.censor.core.util.Util.toHexString
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage

class MessageLengthManipulationTest: SniTest<MessageLengthManipulation>(fails = true) {
    override fun targetManipulations(): Collection<MessageLengthManipulation> {
        return listOf(
            MessageLengthManipulation(0.0, CoreClientHelloMessage::class.java),
            MessageLengthManipulation(0.5, CoreClientHelloMessage::class.java),
            MessageLengthManipulation(2.0, CoreClientHelloMessage::class.java),
            MessageLengthManipulation(1.0E34, CoreClientHelloMessage::class.java)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: MessageLengthManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // message length modified correctly, 00 prepended explicitly because we cap message length at ffff intentionally
        val correctMessageLength = "00" + (defaultMessageLength * manipulation.messageLengthModifier).toInt().toHexString(MESSAGE_LENGTH_FIELD_LENGTH)
        val correctRecordLength = (defaultMessageLength + MESSAGE_LENGTH_FIELD_LENGTH + MESSAGE_VERSION_FIELD_LENGTH).toHexString(
            MESSAGE_LENGTH_FIELD_LENGTH)

        assert(actual.contains("0303" + correctRecordLength + "01" + correctMessageLength + "0303", ignoreCase = true))
    }
}