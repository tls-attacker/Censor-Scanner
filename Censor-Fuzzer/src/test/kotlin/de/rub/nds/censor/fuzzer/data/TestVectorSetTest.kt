package de.rub.nds.censor.fuzzer.data

import de.rub.nds.censor.core.data.ServerAddress
import de.rub.nds.censor.core.network.Ipv4Address
import de.rub.nds.censor.fuzzer.combination.instantiation.AdditionalEntriesInstantiation
import de.rub.nds.censor.fuzzer.combination.instantiation.VersionInstantiation
import de.rub.nds.censor.fuzzer.combination.strategy.NameLengthStrategy
import de.rub.nds.censor.fuzzer.combination.strategy.RecordVersionStrategy
import de.rub.nds.censor.fuzzer.combination.strategy.SniEntriesStrategy
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*

class TestVectorSetTest {

    @Test
    fun testSerialization() {
        val vectorSet = ServerEvaluation(
            2,
            ServerAddress(Ipv4Address("127.0.0.1"), 443, "example.com"),
            listOf(),
            listOf(
                TestVector(
                    mutableListOf(
                        RecordVersionStrategy().apply { instantiate(VersionInstantiation.INVALID_BIGGER) },
                        SniEntriesStrategy("harmless", "original").apply { instantiate(AdditionalEntriesInstantiation.MAX) }
                    ),
                ),
                TestVector(
                    mutableListOf()
                ),
                TestVector(
                    mutableListOf(
                        NameLengthStrategy(123, 321)
                    )
                )
            )
        )

        val serializedSet = Json.encodeToString(vectorSet)
        val deserializedSet = Json.decodeFromString<ServerEvaluation>(serializedSet)
        val serializedSet2 = Json.encodeToString(deserializedSet)

        assertEquals(serializedSet, serializedSet2)

    }
}