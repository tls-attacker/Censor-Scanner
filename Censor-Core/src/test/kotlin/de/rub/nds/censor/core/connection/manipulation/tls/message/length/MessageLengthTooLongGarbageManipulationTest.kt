package de.rub.nds.censor.core.connection.manipulation.tls.message.length

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants.GARBAGE_BYTE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_FIELD_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_TO_OUTER
import de.rub.nds.censor.core.util.Util.toHexString
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import org.junit.jupiter.api.Assertions

class MessageLengthTooLongGarbageManipulationTest: SniTest<MessageLengthTooLongGarbageManipulation>(fails = true) {
    override fun targetManipulations(): Collection<MessageLengthTooLongGarbageManipulation> {
        return listOf(
            MessageLengthTooLongGarbageManipulation(0, CoreClientHelloMessage::class.java),
            MessageLengthTooLongGarbageManipulation(20, CoreClientHelloMessage::class.java)
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: MessageLengthTooLongGarbageManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // check if garbage bytes present at end of extensions
        Assertions.assertEquals(actual.substring(actual.length - manipulation.garbageCount * 2), GARBAGE_BYTE.toHexString().repeat(manipulation.garbageCount))

        // check correct modification of all super lengths with garbage count
        val correctOffset = manipulation.garbageCount
        val correctMessageLength = (defaultMessageLength + correctOffset).toHexString(MESSAGE_LENGTH_SIZE)

        assert(actual.contains((defaultMessageLength + correctOffset + MESSAGE_LENGTH_TO_OUTER).toHexString(MESSAGE_LENGTH_FIELD_LENGTH) + "01" + correctMessageLength + "0303", ignoreCase = true))
    }
}