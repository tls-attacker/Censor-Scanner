package de.rub.nds.censor.core.connection.manipulation.tls

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_OFFSET_FOR_TOTAL_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_MAX_RECORD_SIZE_CORRECT
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_MAX_RECORD_SIZE_POSSIBLE
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import org.junit.jupiter.api.Assertions

class AddCipherSuitesAsPaddingManipulationTest: SniTest<AddCipherSuitesAsPaddingManipulation>() {
    override fun targetManipulations(): Collection<AddCipherSuitesAsPaddingManipulation> {
        return listOf(
            AddCipherSuitesAsPaddingManipulation(TLS_MAX_RECORD_SIZE_CORRECT),
            AddCipherSuitesAsPaddingManipulation(TLS_MAX_RECORD_SIZE_POSSIBLE)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: AddCipherSuitesAsPaddingManipulation, exception: Exception?) {
        val message = connection.state.workflowTrace.lastReceivingAction.receivedMessages[0]
        if (message !is CoreClientHelloMessage) throw Exception()

        var bytesToAdd = manipulation.padToSize - defaultMessageLength - MESSAGE_OFFSET_FOR_TOTAL_SIZE
        if (bytesToAdd % 2 == 1) {
            bytesToAdd -= 1
        }

        Assertions.assertEquals(bytesToAdd + defaultMessageLength, message.getLength().value) // message length corectly padded
        Assertions.assertEquals(bytesToAdd + defaultCipherSuitesLength, message.getCipherSuiteLength().value) // Cipher suites correct size
    }
}