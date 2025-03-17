package de.rub.nds.censor.core.connection.manipulation.tls.extension;

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import java.lang.Exception

class OverrideExtensionTypeManipulationTest: SniTest<OverrideExtensionTypeManipulation>() {
    override fun targetManipulations(): Collection<OverrideExtensionTypeManipulation> {
        return listOf(
            OverrideExtensionTypeManipulation(ServerNameIndicationExtensionMessage::class.java, byteArrayOf(0x00, 0x00)),
            OverrideExtensionTypeManipulation(ServerNameIndicationExtensionMessage::class.java, byteArrayOf(-1, -1)),
            OverrideExtensionTypeManipulation(ServerNameIndicationExtensionMessage::class.java, byteArrayOf(-1, 0x00))
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: OverrideExtensionTypeManipulation,
        exception: Exception?
    ) {
        val expected = manipulation.extensionType
        assert((connection.state.workflowTrace.lastReceivingAction.receivedMessages[0] as CoreClientHelloMessage)
            .getExtensions().any { it.extensionType.value.contentEquals(expected)})
    }
}
