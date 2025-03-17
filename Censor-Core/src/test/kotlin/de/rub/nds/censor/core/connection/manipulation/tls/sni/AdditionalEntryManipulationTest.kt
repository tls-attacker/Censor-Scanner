package de.rub.nds.censor.core.connection.manipulation.tls.sni

import de.rub.nds.censor.core.connection.TlsConnection
import org.junit.jupiter.api.Assertions.*
import java.lang.Exception

class AdditionalEntryManipulationTest: SniTest<AdditionalEntryManipulation>() {
    override fun targetManipulations(): Collection<AdditionalEntryManipulation> {
        return listOf(
            AdditionalEntryManipulation("secondwebsite.com", 0),
            AdditionalEntryManipulation("sdfasldf hs", 1),
            AdditionalEntryManipulation("", 1),
            AdditionalEntryManipulation("secondwebsite.com", 100),
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: AdditionalEntryManipulation, exception: Exception?) {
        val expectedHostname = manipulation.hostName
        val expectedAmount = manipulation.amount
        val expectedNameLength = expectedHostname.length
        val expectedListLength = 3 + DEFAULT_TEST_HOSTNAME.length + expectedAmount * (3 + expectedNameLength)
        val expectedExtensionLength = expectedListLength + 2
        val actualAmount = connection.getSni().serverNameList.size
        val actualListLength = connection.getSni().serverNameListLength.value
        val actualExtensionLength = connection.getSni().extensionLength.value

        assertEquals(expectedAmount + 1, actualAmount)
        assertEquals(expectedListLength, actualListLength)
        assertEquals(expectedExtensionLength, actualExtensionLength)

        // check for correct nameLength and name of first element that stays the same
        assertEquals(DEFAULT_TEST_HOSTNAME, connection.getFirstEntry().decodeToString())
        assertEquals(DEFAULT_TEST_HOSTNAME.length, connection.getSni().serverNameList[0].serverNameLength.value)

        // check all other name lengths and names
        (1..<expectedAmount).forEach {
            assertEquals(expectedHostname, connection.getSni().serverNameList[it].serverName.value.decodeToString())
            assertEquals(expectedNameLength, connection.getSni().serverNameList[it].serverNameLength.value)
        }
    }
}