package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants.GARBAGE_BYTE
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import org.junit.jupiter.api.Assertions


class ListLengthTooLongGarbageManipulationTest: SniTest<ListLengthTooLongGarbageManipulation>(fails = true) {
    override fun targetManipulations(): Collection<ListLengthTooLongGarbageManipulation> {
        return listOf(
            ListLengthTooLongGarbageManipulation(0),
            ListLengthTooLongGarbageManipulation(20)
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ListLengthTooLongGarbageManipulation, exception: Exception?) {
        val message = connection.state.workflowTrace.lastReceivingAction.receivedMessages[0]
        if (message !is CoreClientHelloMessage) throw Exception()

        Assertions.assertEquals(defaultMessageLength + manipulation.garbageCount, message.getLength().value)
        Assertions.assertEquals(defaultExtensionsLength + manipulation.garbageCount, message.getExtensionsLength().value)

        val sni = message.getExtension(ServerNameIndicationExtensionMessage::class.java)
        Assertions.assertEquals(defaultSniExtensionLength + manipulation.garbageCount, sni.extensionLength.value)
        Assertions.assertEquals(defaultSniListLength + manipulation.garbageCount, sni.serverNameListLength.value)

        assert(sni.serverNameListBytes.value.toHexString().contains(GARBAGE_BYTE.toHexString(HexFormat.Default).repeat(manipulation.garbageCount)))
    }
}