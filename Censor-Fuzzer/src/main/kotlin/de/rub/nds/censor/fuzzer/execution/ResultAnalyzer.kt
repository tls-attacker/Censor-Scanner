package de.rub.nds.censor.fuzzer.execution

import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.fuzzer.config.FuzzerConfig
import de.rub.nds.censor.fuzzer.data.ServerEvaluation
import de.rub.nds.censor.fuzzer.data.TestVector
import de.rub.nds.censor.fuzzer.extractMaximalTestVectors
import de.rub.nds.censor.fuzzer.extractMinimalTestVectors
import org.apache.logging.log4j.kotlin.Logging
import java.io.File
import java.time.LocalDate

class ResultAnalyzer(
    private val serverEvaluation: ServerEvaluation,
    private val fuzzerConfig: FuzzerConfig,
    private val scanTime: Long,
) {
    fun interpretResults() {

        logger.info("Starting to analyze results!")
        // build map
        val sortedResultsMap = HashMap<ConnectionReturn, MutableList<TestVector>>()
        ConnectionReturn.entries.forEach { sortedResultsMap[it] = mutableListOf() }
        serverEvaluation.vectors.forEach { sortedResultsMap[it.result]!!.add(it) }
        logger.info("Sorting done!")

        val workingScoreMap = HashMap<String, Int>()
        val failingScoreMap = HashMap<String, Int>()
        File("${fuzzerConfig.outputFileIdentifier}_results.txt").printWriter().use { out ->
            // print general scan details
            out.println("Scan took: ${scanTime/60000} minutes")
            out.println("Scanned on date: ${LocalDate.now()}\n")
            out.println("Config values:\n${fuzzerConfig.toHumanReadable()}\n")

            out.println("Server behavior on control vector: ${serverEvaluation.serverBehaviorOnControlVector}")
            if (fuzzerConfig.scanType == CensorScanType.DIRECT) {
                out.println("Default Server Title: ${serverEvaluation.defaultServerAnswerTitle}")
            }
            logger.info("Wrote general info!")

            // print working
            out.println("Working strategies - ${sortedResultsMap[ConnectionReturn.WORKING]!!.size}:")
            sortedResultsMap[ConnectionReturn.WORKING]!!.forEach {
                out.println("  ${it.mutatedStrategies}")
                it.mutatedStrategies.forEach { str ->
                    val instantiation = str.toString()
                    workingScoreMap[instantiation] = workingScoreMap.getOrDefault(instantiation, 0) + 1
                }
            }
            logger.info("Wrote working!")

            if (fuzzerConfig.writeAllResultTypes) {
                // print already default separately
                out.println("\nAlready default (unmodified message - not executed) - ${sortedResultsMap[ConnectionReturn.ALREADY_DEFAULT]!!.size}:")
                sortedResultsMap[ConnectionReturn.ALREADY_DEFAULT]!!.forEach { out.println("  ${it.mutatedStrategies}") }
                logger.info("Wrote already default!")

                // print inapplicable separately
                out.println("\nInapplicable combination (not executed) - ${sortedResultsMap[ConnectionReturn.INAPPLICABLE]!!.size}:")
                sortedResultsMap[ConnectionReturn.INAPPLICABLE]!!.forEach { out.println("  ${it.mutatedStrategies}") }
                logger.info("Wrote inapplicable!")
            }

            // print all other
            sortedResultsMap.forEach { (connectionReturn, tlsServerScanTestVectors) ->
                if (tlsServerScanTestVectors.isNotEmpty() && connectionReturn != ConnectionReturn.WORKING &&
                    connectionReturn != ConnectionReturn.ALREADY_DEFAULT &&
                    connectionReturn != ConnectionReturn.INAPPLICABLE
                ) {
                    out.println("\nResults for $connectionReturn - ${tlsServerScanTestVectors.size}:")
                    tlsServerScanTestVectors.forEach {
                        out.println("  ${it.mutatedStrategies}")
                        it.mutatedStrategies.forEach { str ->
                            val instantiation = str.toString()
                            failingScoreMap[instantiation] = failingScoreMap.getOrDefault(instantiation, 0) + 1
                        }
                    }
                }
            }
            logger.info("Wrote other!")

            // print maximal and minimal working and non-working strategies
            if (fuzzerConfig.writeAllResultTypes) {
                out.println("\nMaximal working strategies:")
                extractMaximalWorkingStrategies().forEach { out.println("  ${it.mutatedStrategies}") }

                out.println("\nMinimal working strategies:")
                extractMinimalWorkingStrategies().forEach { out.println("  ${it.mutatedStrategies}") }

                out.println("\nMaximal failing strategies:")
                extractMaximalFailingStrategies().forEach { out.println("  ${it.mutatedStrategies}") }

                out.println("\nMinimal failure-inducing strategies:")
                extractMinimalFailureInducingStrategies().forEach { out.println("  ${it.mutatedStrategies}") }

                logger.info("Wrote maximal and minimal working and failing strategies!")
            }

            out.println("\nWorking Percentage of instantiations:")
            val allInstantiations: MutableSet<String> = workingScoreMap.keys.toMutableSet()
            allInstantiations.addAll(failingScoreMap.keys.toMutableSet())
            val workingPercentageMap = HashMap<String, Double>()
            allInstantiations.forEach {
                val timesWorking = workingScoreMap.getOrDefault(it, 0)
                val timesFailing = failingScoreMap.getOrDefault(it, 0)
                workingPercentageMap[it] = (timesWorking.toDouble() / (timesWorking + timesFailing).toDouble()) * 100
            }
            val sortedMap = workingPercentageMap.toList()
                .sortedBy { (_, value) -> -value }
                .toMap()
            sortedMap.forEach { out.println(" ${it.key} [${it.value}%]") }
            logger.info("Wrote statistics!")
        }
    }

    private fun extractMaximalWorkingStrategies(): List<TestVector> {
        return extractMaximalTestVectors(serverEvaluation.vectors.filter { it.result == ConnectionReturn.WORKING }, serverEvaluation.testStrength)
    }

    private fun extractMinimalFailureInducingStrategies(): List<TestVector> {
        return extractMinimalTestVectors(serverEvaluation.vectors.filter { it.result != ConnectionReturn.WORKING && it.result != ConnectionReturn.ALREADY_DEFAULT && it.result != ConnectionReturn.INAPPLICABLE }, serverEvaluation.testStrength)
    }

    private fun extractMaximalFailingStrategies(): List<TestVector> {
        return extractMaximalTestVectors(serverEvaluation.vectors.filter { it.result != ConnectionReturn.WORKING && it.result != ConnectionReturn.ALREADY_DEFAULT && it.result != ConnectionReturn.INAPPLICABLE }, serverEvaluation.testStrength)
    }

    private fun extractMinimalWorkingStrategies(): List<TestVector> {
        return extractMinimalTestVectors(serverEvaluation.vectors.filter { it.result == ConnectionReturn.WORKING }, serverEvaluation.testStrength)
    }

    companion object : Logging
}