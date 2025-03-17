package de.rub.nds.censor.core.connection.manipulation.tls

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.censor.core.connection.manipulation.tls.version.TlsVersionManipulation
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion
import org.junit.jupiter.api.Assertions.assertArrayEquals

class TlsVersionManipulationTest: ManipulationTest<TlsVersionManipulation>() {
    override fun targetManipulations(): Collection<TlsVersionManipulation> {
        return listOf(
            TlsVersionManipulation(ProtocolVersion.TLS10),
            TlsVersionManipulation(ProtocolVersion.TLS11),
            TlsVersionManipulation(ProtocolVersion.TLS12),
            TlsVersionManipulation(ProtocolVersion.TLS13)
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: TlsVersionManipulation,
        exception: Exception?
    ) {
        val expected = if (manipulation.version == ProtocolVersion.TLS13) {
            ProtocolVersion.TLS12.value
        } else {
            manipulation.version.value
        }
        val actualRecordVersion = connection.getRecord().protocolVersion.value
        val actualMessageVersion = connection.getClientHello().protocolVersion.value
        assertArrayEquals(expected, actualRecordVersion)
        assertArrayEquals(expected, actualMessageVersion)
    }
}