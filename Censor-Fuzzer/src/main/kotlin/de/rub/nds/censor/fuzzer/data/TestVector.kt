package de.rub.nds.censor.fuzzer.data

import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.fuzzer.combination.strategy.ExtensionStrategy
import de.rub.nds.censor.fuzzer.combination.strategy.SniEntriesStrategy
import de.rub.nds.censor.fuzzer.combination.strategy.Strategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Vector of strategies to execute against a server. Also holds the results later.
 */
@Serializable
data class TestVector(
    // instantiated and maybe mutated strategies to test or tested against the server
    val instantiatedStrategies: MutableList<Strategy<*>> = mutableListOf(),
    // only the mutated strategies for easy serialization
    val mutatedStrategies: MutableList<Strategy<*>> = mutableListOf(),
    // the ConnectionReturn of the server
    var result: ConnectionReturn = ConnectionReturn.UNSET,
    // any potential exceptions encountered during the connection
    // TODO: make Exceptions serializable
    @Transient
    var exception: Exception? = null
) {

    override fun toString(): String {
        return "TlsServerScanTestVector(setStrategies=$mutatedStrategies, result=$result${if (exception != null) ", exception=$exception" else ""})"
    }

    fun fillMutatedStrategiesFromInstantiatedStrategies() {
        mutatedStrategies.clear()
        mutatedStrategies.addAll(instantiatedStrategies.filter { strategy -> strategy.instantiation != strategy.defaultInstantiation })
    }

    fun fillInstantiatedStrategiesFromMutatedStrategies(allDefaultStrategies: List<Strategy<*>>) {
        instantiatedStrategies.clear()
        instantiatedStrategies.addAll(allDefaultStrategies)

        for (strategy in allDefaultStrategies) {
            for (mutatedStrategy in mutatedStrategies) {
                if (strategy.javaClass == mutatedStrategy.javaClass) {
                    instantiatedStrategies.add(mutatedStrategy)
                } else {
                    instantiatedStrategies.add(strategy)
                }
            }
        }
    }
}