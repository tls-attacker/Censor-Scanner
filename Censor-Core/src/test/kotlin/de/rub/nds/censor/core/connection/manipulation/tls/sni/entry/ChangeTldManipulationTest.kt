package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import org.junit.jupiter.api.Assertions.assertEquals
import java.lang.Exception

class ChangeTldManipulationTest: SniTest<ChangeTldManipulation>(fails = true) {
    override fun targetManipulations(): Collection<ChangeTldManipulation> {
        return listOf(
            ChangeTldManipulation(0, "com"),
            ChangeTldManipulation(0, "COM"),
            ChangeTldManipulation(0, "..."),
            ChangeTldManipulation(0, "    "),
            ChangeTldManipulation(0, "")
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ChangeTldManipulation, exception: Exception?) {
        if (manipulation.tld == "com") {
            // we expect failure due to default
            assert((exception as NotConnectableException).reason == ConnectionReturn.ALREADY_DEFAULT)
        } else {
            val expected = DEFAULT_TEST_HOSTNAME.substringBeforeLast(".") + "." + manipulation.tld
            val actual = connection.getFirstEntry().decodeToString()
            assertEquals(expected, actual)
            // also check length
            assertEquals(
                DEFAULT_TEST_HOSTNAME.length - 3 + manipulation.tld.length,
                connection.getSni().serverNameList[0].serverNameLength.value
            )
        }
    }
}