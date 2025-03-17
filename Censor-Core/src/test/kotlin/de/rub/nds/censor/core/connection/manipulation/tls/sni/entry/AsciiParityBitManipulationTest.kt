package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import java.lang.Exception

class AsciiParityBitManipulationTest: SniTest<AsciiParityBitManipulation>() {
    override fun targetManipulations(): Collection<AsciiParityBitManipulation> {
        return listOf(AsciiParityBitManipulation(0))
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: AsciiParityBitManipulation, exception: Exception?) {
        val expected = "e5f8e1edf0ece5aee3efed".fromHexString()
        val actual = connection.getFirstEntry()
        assertArrayEquals(expected, actual)
    }
}