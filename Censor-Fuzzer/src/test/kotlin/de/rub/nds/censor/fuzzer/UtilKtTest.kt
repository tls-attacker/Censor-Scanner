package de.rub.nds.censor.fuzzer

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.extension.PaddingExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.version.TlsVersionManipulation
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.ManipulationConstants
import de.rub.nds.censor.core.network.Ipv4Address
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion
import de.rub.nds.tlsattacker.core.util.ProviderUtil
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class UtilKtTest {

    @Test
    fun getAllKSizedSubsets() {
        val input = listOf(1, 2, 3, 4, 5)
        val outputStrength0 = setOf<List<Int>>()
        val outputStrength2 = setOf(
            listOf(1, 2), listOf(1, 3), listOf(1, 4), listOf(1, 5),
            listOf(2, 3), listOf(2, 4), listOf(2, 5),
            listOf(3, 4), listOf(3, 5),
            listOf(4, 5)
        )
        val outputStrength4 = setOf(
            listOf(1, 2, 3, 4), listOf(1, 2, 3, 5), listOf(1, 2, 4, 5), listOf(1, 3, 4, 5), listOf(2, 3, 4, 5)
        )
        val outputStrength5 = setOf(listOf(1, 2, 3, 4, 5))

        assertSetWithListEquals(outputStrength0, getAllKSizedSubsets(input, 0).toSet())
        assertSetWithListEquals(outputStrength2, getAllKSizedSubsets(input, 2).toSet())
        assertSetWithListEquals(outputStrength4, getAllKSizedSubsets(input, 4).toSet())
        assertSetWithListEquals(outputStrength5, getAllKSizedSubsets(input, 5).toSet())
    }

    private fun assertSetWithListEquals(expected: Set<List<*>>, actual: Set<List<*>>) {
        if (expected.size != actual.size) {
            throw AssertionError("Sets of unequal size. Expected ${expected.size}, actual: ${actual.size}")
        }

        actual.forEach { it1 ->
            var equals = false
            for (it2 in expected) {
                if (it1 == it2) {
                    equals = true
                    break
                }
            }
            if (!equals) {
                throw AssertionError("List $it1 not found in expected.")
            }
        }
    }
}