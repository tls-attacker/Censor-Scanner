package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import org.junit.jupiter.api.Assertions.assertEquals
import java.lang.Exception

class AddSubdomainManipulationTest : SniTest<AddSubdomainManipulation>() {
    override fun targetManipulations(): Collection<AddSubdomainManipulation> {
        return listOf(
            AddSubdomainManipulation(0, "www"),
            AddSubdomainManipulation(0, "123"),
            AddSubdomainManipulation(0, "..."),
            AddSubdomainManipulation(0, "")
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: AddSubdomainManipulation, exception: Exception?) {
        val expected = "${manipulation.subdomain}.$DEFAULT_TEST_HOSTNAME"
        val actual = connection.getFirstEntry().decodeToString()
        assertEquals(expected, actual)
        // also check length
        assertEquals(DEFAULT_TEST_HOSTNAME.length + manipulation.subdomain.length + 1, connection.getSni().serverNameList[0].serverNameLength.value)
    }

}