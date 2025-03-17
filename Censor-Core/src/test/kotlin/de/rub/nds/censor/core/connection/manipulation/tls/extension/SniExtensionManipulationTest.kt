package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import org.junit.jupiter.api.Assertions.assertEquals
import java.lang.Exception

class SniExtensionManipulationTest: ManipulationTest<SniExtensionManipulation>() {
    override fun targetManipulations(): Collection<SniExtensionManipulation> {
        return listOf(
            SniExtensionManipulation(DEFAULT_TEST_HOSTNAME, true),
            SniExtensionManipulation("", true),
            SniExtensionManipulation("myverycoolhostname", true),
            SniExtensionManipulation(".......................", true),
            SniExtensionManipulation(DEFAULT_TEST_HOSTNAME, false)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: SniExtensionManipulation, exception: Exception?) {
        val expected = manipulation.hostName
        if(manipulation.enable) {
            val sni = (connection.state.workflowTrace.lastReceivingAction.receivedMessages[0] as CoreClientHelloMessage).getExtension(ServerNameIndicationExtensionMessage::class.java)
            assert(sni.serverNameList.size == 1)
            assertEquals(expected, sni.serverNameList[0].serverName.value.decodeToString())
            assertEquals(expected.length, sni.serverNameList[0].serverNameLength.value.toInt())
            assertEquals(0x00, sni.serverNameList[0].serverNameType.value.toInt())
            assertEquals(expected.length+3, sni.serverNameListLength.value.toInt())
            assertEquals(expected.length+5, sni.extensionLength.value)
        } else {
            assert(
                connection.state.workflowTrace.lastReceivingAction.receivedMessages
                    .filterIsInstance(ClientHelloMessage::class.java)[0].extensions.none {
                    it.extensionType.value.contentEquals(
                        byteArrayOf(0x00)
                    )
                }
            )
        }
    }
}