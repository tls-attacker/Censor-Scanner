package de.rub.nds.censor.core.connection.manipulation.tls.sni

import de.rub.nds.censor.core.connection.TlsConnection
import org.junit.jupiter.api.Assertions.assertEquals

class StripListEntriesManipulationTest: SniTest<StripListEntriesManipulation>() {

    override fun targetManipulations(): Collection<StripListEntriesManipulation> {
        return listOf(StripListEntriesManipulation())
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: StripListEntriesManipulation,
        exception: Exception?
    ) {
        val expectedExtensionLength = 0
        val actualExtensionLength = connection.getSni().extensionLength.value

        assertEquals(expectedExtensionLength, actualExtensionLength)
        assert(connection.getSni().extensionContent.value.isEmpty())
    }
}