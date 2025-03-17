package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants
import org.junit.jupiter.api.Assertions.assertEquals

class PadHostnameToMaximumManipulationTest: SniTest<PadHostnameToMaximumManipulation>() {
    override fun targetManipulations(): Collection<PadHostnameToMaximumManipulation> {
        return listOf(
            PadHostnameToMaximumManipulation(0)
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: PadHostnameToMaximumManipulation,
        exception: Exception?
    ) {
        val expectedHostname = DEFAULT_TEST_HOSTNAME + "q".repeat(ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE - 5001 - DEFAULT_TEST_HOSTNAME.length)
        val expectedLength = expectedHostname.length
        val actualHostname = connection.getFirstEntry().decodeToString()
        val actualLength = connection.getSni().serverNameList[0].serverNameLength.value
        assertEquals(expectedHostname, actualHostname)
        assertEquals(expectedLength, actualLength)
    }
}