package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import org.junit.jupiter.api.Assertions.*
import java.lang.Exception

class SpongebobCaseManipulationTest: SniTest<SpongebobCaseManipulation>() {
    override fun targetManipulations(): Collection<SpongebobCaseManipulation> {
        return listOf(
            SpongebobCaseManipulation(0)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: SpongebobCaseManipulation, exception: Exception?) {
        val expected = "eXaMpLe.cOm"
        val actual = connection.getFirstEntry().decodeToString()
        assertEquals(expected, actual)
    }
}