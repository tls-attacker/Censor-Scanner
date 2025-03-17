package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import org.junit.jupiter.api.Assertions.assertEquals

class RemoveSniExtensionsManipulationTest: SniTest<RemoveSniExtensionsManipulation>() {
    override fun targetManipulations(): Collection<RemoveSniExtensionsManipulation> {
        return listOf(RemoveSniExtensionsManipulation())
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: RemoveSniExtensionsManipulation,
        exception: Exception?
    ) {
        assertEquals(0, connection.getClientHello().extensions.count { it is ServerNameIndicationExtensionMessage })
    }
}