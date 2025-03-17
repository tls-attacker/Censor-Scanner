package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import org.junit.jupiter.api.Assertions.*
import java.lang.Exception

class NameLengthManipulationTest: SniTest<NameLengthManipulation>() {
    override fun targetManipulations(): Collection<NameLengthManipulation> {
        return listOf(
            NameLengthManipulation(0, 0),
            NameLengthManipulation(0, 1),
            NameLengthManipulation(0, 10),
            NameLengthManipulation(0, 0xffff),
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: NameLengthManipulation, exception: Exception?) {
        val expected = manipulation.length
        when (expected) {
            0 -> assertEquals("0000006578616D706C652E636F6D", connection.getSni().serverNameListBytes.value.toHexString().uppercase())
            1 -> assertEquals("0000016578616D706C652E636F6D", connection.getSni().serverNameListBytes.value.toHexString().uppercase())
            10 -> assertEquals("00000A6578616D706C652E636F6D", connection.getSni().serverNameListBytes.value.toHexString().uppercase())
            0xffff -> assertEquals("00FFFF6578616D706C652E636F6D", connection.getSni().serverNameListBytes.value.toHexString().uppercase())
        }
    }
}