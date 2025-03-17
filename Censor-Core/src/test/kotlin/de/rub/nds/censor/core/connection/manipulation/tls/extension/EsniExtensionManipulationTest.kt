package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import java.lang.Exception

class EsniExtensionManipulationTest: ManipulationTest<EsniExtensionManipulation>() {
    override fun targetManipulations(): Collection<EsniExtensionManipulation> {
        return listOf(
            EsniExtensionManipulation(true),
            EsniExtensionManipulation(false)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: EsniExtensionManipulation, exception: Exception?) {
        val expected = byteArrayOf(0xFF.toByte(), 0xCE.toByte())
        if (manipulation.enable) {
            assert(
                connection.state.workflowTrace.lastReceivingAction.receivedMessages
                    .filterIsInstance(ClientHelloMessage::class.java)[0].extensions.any {
                    it.extensionType.value.contentEquals(
                        expected
                    )
                }
            )
        } else {
            assert(
                connection.state.workflowTrace.lastReceivingAction.receivedMessages
                    .filterIsInstance(ClientHelloMessage::class.java)[0].extensions.none {
                    it.extensionType.value.contentEquals(
                        expected
                    )
                }
            )
        }
    }

}