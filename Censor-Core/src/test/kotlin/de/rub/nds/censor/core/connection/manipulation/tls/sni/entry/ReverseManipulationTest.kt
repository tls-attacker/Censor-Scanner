package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import org.junit.jupiter.api.Assertions.assertEquals
import java.lang.Exception

class ReverseManipulationTest: SniTest<ReverseManipulation>() {
    override fun targetManipulations(): Collection<ReverseManipulation> {
        return listOf(
            ReverseManipulation(0)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ReverseManipulation, exception: Exception?) {
        val expected = "moc.elpmaxe"
        val actual = connection.getFirstEntry().decodeToString()
        assertEquals(expected, actual)
    }
}