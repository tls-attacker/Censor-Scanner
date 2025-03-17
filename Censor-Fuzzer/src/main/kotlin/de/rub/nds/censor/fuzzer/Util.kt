package de.rub.nds.censor.fuzzer

import de.rub.nds.censor.fuzzer.data.TestVector


fun <type> getAllKorLessSizedSubsets(list: List<type>, remaining: Int) = sequence {
    (1..remaining).forEach { i ->
        yieldAll(getAllKSizedSubsets(list, i))
    }
}

/**
 * Yields all k-sized subsets of the given set. Parameters are lists but still operates on sets, i.e. does not return
 * 1,3 and 3,1 as two different combinations for input (1,2,3,4,5)
 */
fun <type> getAllKSizedSubsets(list: List<type>, remaining: Int, chosen: List<type> = listOf()): Sequence<List<type>> =
    sequence {

        // apply chosen to results when remaining equals 0
        if (remaining == 0 || list.isEmpty()) {
            if (chosen.isNotEmpty()) {
                yield(chosen)
            }
            return@sequence
        }
        // if enough elements remaining produce a combination without first element
        if (list.size > remaining) {
            yieldAll(getAllKSizedSubsets(list.drop(1), remaining, chosen))
        }
        // in any case produce combination with first element
        val newChosen = chosen.toMutableList()
        newChosen.add(list[0])
        yieldAll(getAllKSizedSubsets(list.drop(1), remaining - 1, newChosen))
    }

/**
 * Returns all combinations of entries from the given lists. e.g (1,2),(a,b) would return (1,a),(1,b),(2,a)(2,b)
 */
fun <type> getAllCombinationsOfEntries(lists: List<List<type>>): Sequence<List<type>> = sequence {
    if (!lists.all { it.size == lists[0].size }) {
        throw IllegalArgumentException("All entered lists must be of the same size to combine")
    }
    yieldAll(getAllCombinationsOfEntriesRecursive(listOf(), lists))
}

/**
 * Recursive function for yielding combinations of entries. // TODO: test
 */
private fun <type> getAllCombinationsOfEntriesRecursive(alreadySet: List<type>, lists: List<List<type>>):
        Sequence<List<type>> = sequence {
    if (lists.isEmpty()) {
        yield(alreadySet)
        return@sequence
    }
    lists[0].forEach {
        yieldAll(getAllCombinationsOfEntriesRecursive(alreadySet + it, lists.subList(1, lists.size)))
    }
}

/**
 * Extracts the minimal set of test vectors in regard to the analyzed set of strategies. I.e. when the strategies
 * (A,B) are present the other present combination (A,B,C) will not be yielded. Can be used to extract a minimal
 * sets of failure-inducing or working combinations.
 *
 * @param testVectors [TestVector]s that are considered for extraction.
 */
fun extractMinimalTestVectors(testVectors: List<TestVector>, testStrength: Int): List<TestVector> {

    val results = mutableListOf<TestVector>()
    val toAnalyze = testVectors.toMutableList()

    (1..testStrength).forEach { strength ->
        val roundResults = mutableListOf<TestVector>()
        // add all vectors with set test strength
        toAnalyze
            // filter all vectors with set test strength
            .filter { it.mutatedStrategies.size == strength }
            .also {
                // remove from toAnalyze and add to results
                roundResults.addAll(it)
                toAnalyze.removeAll(it)
            }
        // remove all from toAnalyze that contain the result vectors
        toAnalyze.removeAll { largerVector ->
            roundResults.find { extractedVector ->
                instantiatedStrategiesAreSubset(extractedVector, largerVector)
            } != null
        }
        results.addAll(roundResults)
    }
    return results
}

/**
 * Extracts the maximal set of test vectors in regard to the analyzed strategies. I.e. when the strategies (A,B,C)
 * are present the also present combination (A,B) will not be yielded as it is a subset of (A,B,C). Can be used to
 * extract the maximal sets of failure-inducing or working combinations.
 */
fun extractMaximalTestVectors(testVectors: List<TestVector>, testStrength: Int): List<TestVector> {

    val results = mutableListOf<TestVector>()
    val toAnalyze = testVectors.toMutableList()

    (testStrength downTo 1).forEach { strength ->
        val roundResults = mutableListOf<TestVector>()
        // add all vectors with set test strength
        toAnalyze
            // filter all vectors with set test strength
            .filter { it.mutatedStrategies.size == strength }
            .also {
                // remove from toAnalyze and add to results
                roundResults.addAll(it)
                toAnalyze.removeAll(it)
            }
        // remove all from toAnalyze that contain the result vectors
        toAnalyze.removeAll { smallerVector ->
            roundResults.find { extractedVector ->
                instantiatedStrategiesAreSubset(smallerVector, extractedVector)
            } != null
        }
        results.addAll(roundResults)
    }
    return results
}


/**
 * Returns true when the setStrategies of first are either equal or a subset of the setStrategies of other
 */
private fun instantiatedStrategiesAreSubset(
    first: TestVector,
    other: TestVector
): Boolean {

    return (first.mutatedStrategies.find { firstStrategy ->
        // does the strategy of first have a corresponding strategy in other
        other.mutatedStrategies.find { secondStrategy ->
            firstStrategy.strategyEnum == secondStrategy.strategyEnum
                    && firstStrategy.instantiation == secondStrategy.instantiation
        } == null
    } == null)
}
