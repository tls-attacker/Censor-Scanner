package de.rub.nds.censor.core.connection.manipulation.tls.sni

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.extension.AdditionalSniExtensionManipulation
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import org.junit.jupiter.api.Assertions.assertEquals

class AdditionalSniExtensionManipulationTest: SniTest<AdditionalSniExtensionManipulation>(fails = true) {

    private val defaultTestHostnameOverride = "example2.com"

    override fun targetManipulations(): Collection<AdditionalSniExtensionManipulation> {
        return listOf(
            AdditionalSniExtensionManipulation(0, defaultTestHostnameOverride),
            AdditionalSniExtensionManipulation(0, DEFAULT_TEST_REPLACEMENT_HOSTNAME),
            AdditionalSniExtensionManipulation(1, defaultTestHostnameOverride),
            AdditionalSniExtensionManipulation(1, DEFAULT_TEST_REPLACEMENT_HOSTNAME),
            AdditionalSniExtensionManipulation(2, defaultTestHostnameOverride),
            AdditionalSniExtensionManipulation(2, DEFAULT_TEST_REPLACEMENT_HOSTNAME),
            AdditionalSniExtensionManipulation(-1, defaultTestHostnameOverride),
            AdditionalSniExtensionManipulation(-1, DEFAULT_TEST_REPLACEMENT_HOSTNAME),
            AdditionalSniExtensionManipulation(-2, defaultTestHostnameOverride),
            AdditionalSniExtensionManipulation(-2, DEFAULT_TEST_REPLACEMENT_HOSTNAME),
            AdditionalSniExtensionManipulation(300, defaultTestHostnameOverride),
            AdditionalSniExtensionManipulation(-300, DEFAULT_TEST_REPLACEMENT_HOSTNAME),
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: AdditionalSniExtensionManipulation,
        exception: Exception?
    ) {
        val expectedHostname = manipulation.hostname
        var expectedIndex = manipulation.place
        if (expectedIndex < 0) {
            expectedIndex += defaultExtensionCount
        }
        if (expectedIndex > defaultExtensionCount || expectedIndex < 0) {
            assert(exception != null && exception is NotConnectableException)
        } else {
            // check for two sni
            assertEquals(2, connection.getClientHello().extensions.count { it is ServerNameIndicationExtensionMessage })

            // check that index of expected hostname is expected index
            val actualIndex = connection.getClientHello().extensions.indexOfFirst { it is ServerNameIndicationExtensionMessage && it.serverNameList[0].serverName.value.decodeToString() == expectedHostname }
            assertEquals(expectedIndex, actualIndex)

            // check that SNI has correct values
            val extension = connection.getClientHello().extensions[actualIndex] as ServerNameIndicationExtensionMessage
            assertEquals(1, extension.serverNameList.size)
            assertEquals(expectedHostname.length, extension.serverNameList[0].serverNameLength.value)
            assertEquals(0x00.toByte(), extension.serverNameList[0].serverNameType.value)
            assertEquals(expectedHostname.length + 3, extension.serverNameListLength.value)
            assertEquals(expectedHostname.length + 5, extension.extensionLength.value)
        }
    }
}