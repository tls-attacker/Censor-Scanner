package de.rub.nds.censor.fuzzer.combination

import de.rub.nds.censor.fuzzer.combination.instantiation.AdditionalEntriesInstantiation
import de.rub.nds.censor.fuzzer.combination.instantiation.PadToMaximumInstantiation
import de.rub.nds.censor.fuzzer.combination.instantiation.ReplaceWithHarmlessInstantiation
import de.rub.nds.censor.fuzzer.combination.strategy.*
import de.rub.nds.censor.fuzzer.constants.Strategies
import de.rub.nds.censor.fuzzer.getAllCombinationsOfEntries
import de.rub.nds.censor.fuzzer.getAllKorLessSizedSubsets
import org.apache.logging.log4j.kotlin.Logging

class Combiner(correctHostname: String, fillerHostname: String) {

    private val strategyBuilder = StrategyBuilder(correctHostname, fillerHostname)
    fun getAllCombinations(testStrength: Int, alwaysDefaultSequences: Set<Strategies>) = sequence {

        // get all applicable strategies
        val allStrategies = Strategies.entries
        val allUsedStrategies = allStrategies.filter { strategy -> !alwaysDefaultSequences.contains(strategy) }
        // reduce test strength if necessary for smaller amount of strategies
        val usedTestStrength: Int = if (testStrength > allUsedStrategies.size) {
            logger.warn("Reducing test strength from $testStrength to number of strategies ${allUsedStrategies.size}")
            allUsedStrategies.size
        } else {
            testStrength
        }

        if (usedTestStrength == 0) {
            yield(allStrategies.map { strategyBuilder.buildDefault(it) })
            return@sequence
        }

        // get all combinations of t values from strategies
        val activatedStrategies = getAllKorLessSizedSubsets(allUsedStrategies, usedTestStrength)

        // for each combination yield all combinations of instantiations
        activatedStrategies.forEach { selectedStrategies ->
            yieldAll(getAllInstantiatedStrategiesForSelection(allStrategies, selectedStrategies))
        }
    }

    /**
     * Returns a sequence of instantiated strategies using only the indicated selected strategies for instantiating.
     * All combinations of instantiations are returned. For the Additional(SNI)Entry strategy, following strategies are
     * applied to different combinations of SNI entries (only first, only last, etc.)
     *
     * @param allStrategies List of all strategies to consider for instantiations
     * @param strategiesToMutate list of strategies that will be considered for parameter mutation
     */
    private fun getAllInstantiatedStrategiesForSelection(
        allStrategies: List<Strategies>,
        strategiesToMutate: List<Strategies>
    ): Sequence<List<Strategy<*>>> = sequence {
        // yield from recursive function but sort beforehand
        yieldAll(getAllInstantiatedStrategiesForSelectionRecursion(allStrategies.sorted(), strategiesToMutate))
    }


    /**
     * Recursive function for getAllInstantiatedStrategiesForSelection.
     *
     * @param strategiesToInstantiateFrom a list of all strategies to use
     * @param strategiesToInstantiate a list of strategies to instantiate, should be subset of strategiesToInstantiateFrom
     * @param instantiatedStrategies intermediate result for recursive calling
     * @param sniEntryIndices, indices of the sni entry to manipulate with sni manipulating strategies, manipulated in
     * @param isBranchedAfterMoreSni indicated that from now on only [SniEntriesStrategy] will be instantiated and that we
     * branched.
     * the recursion when the SniEntry strategy is instantiated.
     */
    private fun getAllInstantiatedStrategiesForSelectionRecursion(
        strategiesToInstantiateFrom: List<Strategies>,
        strategiesToInstantiate: List<Strategies>,
        instantiatedStrategies: List<Strategy<*>> = listOf(),
        sniEntryIndices: List<Int> = listOf(0),
        isBranchedAfterMoreSni: Boolean = false
    ):
            Sequence<List<Strategy<*>>> = sequence {

        if (strategiesToInstantiateFrom.isEmpty()) {
            yield(instantiatedStrategies)
            return@sequence
        }

        // pop strategy to instantiate
        val currentStrategy = strategiesToInstantiateFrom[0]
        val newStrategiesToInstantiateFrom = strategiesToInstantiateFrom.subList(1, strategiesToInstantiateFrom.size)

        // initialize list for next iteration
        var newInstantiatedStrategies: List<Strategy<*>>

        if (strategiesToInstantiate.contains(currentStrategy)) {

            // for all SNI entries combine their instantiations
            val combinedInstantiationsForAllSniEntries =
                getAllCombinationsOfEntries(sniEntryIndices
                    .map { index ->
                        if (isBranchedAfterMoreSni) {
                            // take default as well when we are after SNI instantiation
                            strategyBuilder.buildAllInstantiations(currentStrategy, index)
                        } else {
                            strategyBuilder.buildAllInstantiationsExceptDefault(currentStrategy, index)
                        }
                    }
                ).toList()

            // instantiate for all SNI entries
            combinedInstantiationsForAllSniEntries
                .run {
                    // remove PAD_TO_MAXIMUM if AdditionalEntries MAX present
                    if (instantiatedStrategies.any { strategy -> strategy is SniEntriesStrategy && strategy.instantiation == AdditionalEntriesInstantiation.MAX } &&
                        currentStrategy == Strategies.PAD_TO_MAXIMUM) {
                        combinedInstantiationsForAllSniEntries.filter { strategies -> strategies.all { strategy -> strategy is PadToMaximumStrategy && strategy.instantiation != PadToMaximumInstantiation.PAD_TO_MAXIMUM } }
                    } else {
                        this
                    }
                }
                // remove all that are only default
                .filter { strategies ->
                    !strategies.all { strategy -> strategy.defaultInstantiation == strategy.instantiation }
                    // remove all multiple PAD_TO_MAXIMUM strategies (only makes sense once)
                }.filter { strategies ->
                    strategies.count { strategy -> strategy is PadToMaximumStrategy && strategy.instantiation != strategy.defaultInstantiation } <= 1
                }
                // for each combination add to instantiatedStrategies and continue
                .forEach { strategies ->
                    newInstantiatedStrategies = instantiatedStrategies + strategies

                    when (currentStrategy) {
                        Strategies.ADDITIONAL_ENTRIES -> {
                            // continue with new SNI entries to instantiate based on this instantiation
                            val sniEntriesStrategy = strategies[0] as SniEntriesStrategy
                            yieldAll(
                                getAllInstantiatedStrategiesForSelectionRecursion(
                                    newStrategiesToInstantiateFrom,
                                    strategiesToInstantiate,
                                    newInstantiatedStrategies,
                                    sniEntriesStrategy.getListIndicesToInstantiateForManipulation(),
                                    true
                                )
                            )
                        }

                        Strategies.ADDITIONAL_SNI -> {
                            yieldAll(
                                getAllInstantiatedStrategiesForSelectionRecursion(
                                    newStrategiesToInstantiateFrom,
                                    strategiesToInstantiate,
                                    newInstantiatedStrategies,
                                    listOf(),
                                    isBranchedAfterMoreSni
                                )
                            )
                        }

                        Strategies.REPLACE_WITH_HARMLESS -> {
                            // dont continue as this instantiation is final
                            val sniEntriesToKeepAlternating = strategies
                                .filter { strategy ->
                                    (strategy.instantiation!! as ReplaceWithHarmlessInstantiation) ==
                                            ReplaceWithHarmlessInstantiation.DEFAULT
                                }.map { strategy ->
                                    (strategy as ReplaceWithHarmlessStrategy).index
                                }
                            yieldAll(
                                getAllInstantiatedStrategiesForSelectionRecursion(
                                    newStrategiesToInstantiateFrom,
                                    strategiesToInstantiate,
                                    newInstantiatedStrategies,
                                    sniEntriesToKeepAlternating,
                                    isBranchedAfterMoreSni
                                )
                            )
                        }

                        else -> {
                            // instantiate with this built instantiation
                            yieldAll(
                                getAllInstantiatedStrategiesForSelectionRecursion(
                                    newStrategiesToInstantiateFrom,
                                    strategiesToInstantiate,
                                    newInstantiatedStrategies,
                                    sniEntryIndices,
                                    isBranchedAfterMoreSni
                                )
                            )
                        }
                    }

                }

        } else {
            // instantiate with default value for each index and continue with next iteration
            newInstantiatedStrategies = instantiatedStrategies +
                    sniEntryIndices.map { strategyBuilder.buildDefault(currentStrategy, it) }
            yieldAll(
                getAllInstantiatedStrategiesForSelectionRecursion(
                    newStrategiesToInstantiateFrom,
                    strategiesToInstantiate,
                    newInstantiatedStrategies,
                    sniEntryIndices,
                    isBranchedAfterMoreSni
                )
            )
        }
    }

    companion object : Logging
}