package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import org.junit.jupiter.api.Assertions
import kotlin.Exception

class CapitalizationManipulationTest: SniTest<CapitalizationManipulation>() {
    override fun targetManipulations(): Collection<CapitalizationManipulation> {
        return listOf(
            CapitalizationManipulation(0, listOf(0,2,4)),
            CapitalizationManipulation(0, listOf()),
            CapitalizationManipulation(0, listOf(5))
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: CapitalizationManipulation, exception: Exception?) {
        var expected = ""
        DEFAULT_TEST_HOSTNAME.forEachIndexed { index, c ->
            expected += if (index in manipulation.positions) {
                c.uppercaseChar()
            } else {
                c
            }
        }
        val actual = connection.getFirstEntry().decodeToString()
        Assertions.assertEquals(expected, actual)
    }
}