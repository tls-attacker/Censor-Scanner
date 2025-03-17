package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import org.junit.jupiter.api.Assertions.*
import java.lang.Exception

class OverrideHostnameManipulationTest: SniTest<OverrideHostnameManipulation>() {
    override fun targetManipulations(): Collection<OverrideHostnameManipulation> {
        return listOf(
            OverrideHostnameManipulation(0, ""),
            OverrideHostnameManipulation(0, DEFAULT_TEST_HOSTNAME),
            OverrideHostnameManipulation(0, "!!!!!!!!!!!!!!!!!!!!!!"),
            OverrideHostnameManipulation(0, DEFAULT_TEST_REPLACEMENT_HOSTNAME),

        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: OverrideHostnameManipulation, exception: Exception?) {
        val expectedHostname = manipulation.hostname
        val expectedLength = expectedHostname.length
        val actualHostname = connection.getFirstEntry().decodeToString()
        val actualLength = connection.getSni().serverNameList[0].serverNameLength.value
        assertEquals(expectedHostname, actualHostname)
        assertEquals(expectedLength, actualLength)
    }
}