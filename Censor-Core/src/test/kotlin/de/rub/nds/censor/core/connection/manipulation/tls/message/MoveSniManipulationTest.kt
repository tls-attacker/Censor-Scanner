package de.rub.nds.censor.core.connection.manipulation.tls.message

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest

class MoveSniManipulationTest: SniTest<MoveSniManipulation>() {
    override fun targetManipulations(): Collection<MoveSniManipulation> {
        return listOf(
            MoveSniManipulation(0),
            MoveSniManipulation(1),
            MoveSniManipulation(2),
            MoveSniManipulation(-1),
            MoveSniManipulation(-2),
        )
    }

    override fun analyzeConnectionForTestCase(
        connection: TlsConnection,
        manipulation: MoveSniManipulation,
        exception: Exception?
    ) {
        val expected = if (manipulation.position < 0) {
            connection.getClientHello().extensions.size + manipulation.position
        } else {
            manipulation.position
        }
        // check that expected position has SNI extension
        assert(connection.getClientHello().extensions[expected].extensionType.value
            .contentEquals(byteArrayOf(0x00, 0x00)))
        // check that no other extension is SNI extension
        assert(connection.getClientHello().extensions.filterIndexed { index, _ -> index != expected }
            .none { it.extensionType.value.contentEquals(byteArrayOf(0x00, 0x00)) })
    }
}