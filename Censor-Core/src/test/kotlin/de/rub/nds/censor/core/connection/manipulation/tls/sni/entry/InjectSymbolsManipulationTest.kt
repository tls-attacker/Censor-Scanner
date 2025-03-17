package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import org.junit.jupiter.api.Assertions.assertEquals
import java.lang.Exception

class InjectSymbolsManipulationTest: SniTest<InjectSymbolsManipulation>() {
    override fun targetManipulations(): Collection<InjectSymbolsManipulation> {
        return listOf(
            InjectSymbolsManipulation(0, 0, "".encodeToByteArray()),
            InjectSymbolsManipulation(0, 0, "testinjection".encodeToByteArray()),
            InjectSymbolsManipulation(0, 4, "testinjection".encodeToByteArray()),
            InjectSymbolsManipulation(0, 10, "testinjection".encodeToByteArray()),
            InjectSymbolsManipulation(0, 11, byteArrayOf(0xE2.toByte(), 0x80.toByte(), 0x8E.toByte())),
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: InjectSymbolsManipulation, exception: Exception?) {
        if (manipulation.symbols.decodeToString() == "") {
            assertEquals(DEFAULT_TEST_HOSTNAME, connection.getFirstEntry().decodeToString())
        } else {
            when(manipulation.position) {
                0-> assertEquals("testinjection$DEFAULT_TEST_HOSTNAME", connection.getFirstEntry().decodeToString())
                4-> assertEquals("examtestinjectionple.com", connection.getFirstEntry().decodeToString())
                10-> assertEquals("example.cotestinjectionm", connection.getFirstEntry().decodeToString())
                11-> assertEquals(byteArrayOf(0xE2.toByte(), 0x80.toByte(), 0x8E.toByte()).toList(), connection.getFirstEntry().takeLast(3))
            }
            if (manipulation.position == 11) {
                assertEquals(DEFAULT_TEST_HOSTNAME.length + byteArrayOf(0xE2.toByte(), 0x80.toByte(), 0x8E.toByte()).size, connection.getSni().serverNameList[0].serverNameLength.value)
            } else {
                assertEquals(DEFAULT_TEST_HOSTNAME.length + "testinjection".length, connection.getSni().serverNameList[0].serverNameLength.value)
            }
        }
    }
}