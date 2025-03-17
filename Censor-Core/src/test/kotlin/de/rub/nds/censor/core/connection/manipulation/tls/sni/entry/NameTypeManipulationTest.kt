package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import org.junit.jupiter.api.Assertions.*
import java.lang.Exception

class NameTypeManipulationTest: SniTest<NameTypeManipulation>() {
    override fun targetManipulations(): Collection<NameTypeManipulation> {
        return listOf(
            NameTypeManipulation(0, 0x00),
            NameTypeManipulation(0, 0x01),
            NameTypeManipulation(0, -1),
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: NameTypeManipulation, exception: Exception?) {
        val expected = manipulation.nameType
        val actual = connection.getSni().serverNameList[0].serverNameType.value
        assertEquals(expected, actual)
    }
}