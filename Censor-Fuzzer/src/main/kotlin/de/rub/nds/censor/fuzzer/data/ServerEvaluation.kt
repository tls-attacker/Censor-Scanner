package de.rub.nds.censor.fuzzer.data

import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.data.ServerAddress
import de.rub.nds.censor.fuzzer.combination.Combiner
import de.rub.nds.censor.fuzzer.combination.strategy.*
import de.rub.nds.censor.fuzzer.config.ExcludeStrategies
import de.rub.nds.censor.fuzzer.config.FuzzerConfig
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import org.apache.logging.log4j.kotlin.Logging
import java.io.File

/**
 * Set wrapper for TlsServerScanTestVector. In the future might also hold other details about a server scan
 */
@Serializable
data class ServerEvaluation(
    val testStrength: Int,
    var server: ServerAddress,
    val defaultStrategies: List<Strategy<*>> = listOf(),
    val vectors: List<TestVector>,
    var defaultServerAnswerTitle: String? = null,
    var serverBehaviorOnControlVector: ConnectionReturn = ConnectionReturn.UNSET) {


    /**
     * Encodes this object to the given file. If stripInstantiatedStrategies is set, the instantiatedStrategies are
     * cleared before encoding. Note: they are NOT reset afterwards
     */
    @OptIn(ExperimentalSerializationApi::class)
    fun encodeToStream(fileName: String, stripInstantiatedStrategies: Boolean = true) {
        if (stripInstantiatedStrategies) {
            this.vectors.forEach { it.instantiatedStrategies.clear() }
        }
        Json.encodeToStream(
            this,
            File(fileName).outputStream()
        )
    }

    companion object : Logging {

        private const val INCORRECT_HOSTNAME = "incorrect.com"

        @OptIn(ExperimentalSerializationApi::class)
        fun fromConfig(config: FuzzerConfig): ServerEvaluation {

            val vectors: List<TestVector>
            val defaultStrategies: List<Strategy<*>>

            // extract vectors from given file or generate anew
            if (config.testVectorInputFile != null) {
                logger.info("Using test vectors from given previous result file ${config.testVectorInputFile}")
                // read ServerEvaluation from file and extract

                val serverEvaluation = Json.decodeFromStream<ServerEvaluation>(File(config.testVectorInputFile!!).inputStream())

                defaultStrategies = serverEvaluation.defaultStrategies

                // get working strategies and replace hostname related values
                // hostnames in the sni extension(s) might have been different in previous scans, so we override them
                // here
                vectors = replaceHostnameRelatedValuesInVectors(serverEvaluation.vectors, defaultStrategies, config)


            } else {
                logger.info("Generating new test vectors.")

                defaultStrategies = StrategyBuilder(config.hostname, INCORRECT_HOSTNAME).run {
                    return@run Strategies.entries.map { buildDefault(it) }
                }

                vectors = generateCombinationSequence(
                    config.hostname,
                    INCORRECT_HOSTNAME,
                    config.testStrength,
                    config.excludeStrategies
                ).map {
                    TestVector(it.toMutableList())
                        .also { testVector ->
                            testVector.fillMutatedStrategiesFromInstantiatedStrategies()
                        }
                }.toList()
            }

            return ServerEvaluation(
                config.testStrength,
                ServerAddress(ip = config.extractedIp, port = config.extractedPort, config.hostname),
               defaultStrategies,
                vectors
            )
        }

        /**
         * Returns working strategies and updates the hostname in all strategies to match the config.
         */
        private fun replaceHostnameRelatedValuesInVectors(vectors: List<TestVector>, defaultStrategies: List<Strategy<*>>, config: FuzzerConfig): List<TestVector> {
            return vectors.filter { vector -> vector.result == ConnectionReturn.WORKING }
                .map {
                    it.also { vector ->
                        vector.fillInstantiatedStrategiesFromMutatedStrategies(defaultStrategies)

                        vector.instantiatedStrategies.filterIsInstance<ExtensionStrategy>()
                            .forEach { strategy -> strategy.hostname = config.hostname }

                        vector.instantiatedStrategies.filterIsInstance<MessageLengthStrategy>()
                            .forEach { strategy -> strategy.correctHostname = config.hostname }

                        vector.instantiatedStrategies.filterIsInstance<ExtensionsLengthStrategy>()
                            .forEach { strategy -> strategy.correctHostname = config.hostname }

                        vector.instantiatedStrategies.filterIsInstance<ListLengthStrategy>()
                            .forEach { strategy -> strategy.correctHostname = config.hostname }

                        vector.instantiatedStrategies.filterIsInstance<ExtensionLengthStrategy>()
                            .forEach { strategy -> strategy.correctHostname = config.hostname }

                        vector.instantiatedStrategies.filterIsInstance<NameLengthStrategy>()
                            .forEach { strategy -> strategy.correctLength = config.hostname.length }

                        vector.instantiatedStrategies.filterIsInstance<InjectSymbolStrategy>()
                            .forEach { strategy -> strategy.hostnameLength = config.hostname.length }

                        vector.instantiatedStrategies.filterIsInstance<SniEntriesStrategy>()
                            .forEach { strategy -> strategy.originalHostname = config.hostname }

                        vector.fillMutatedStrategiesFromInstantiatedStrategies()
                    }
            }
        }

        /**
         * Yields a sequence of instantiated [Strategy] combinations to test for the server.
         */
        private fun generateCombinationSequence(
            correctHostname: String,
            fillerHostname: String,
            testStrength: Int = 0,
            excludeStrategies: List<ExcludeStrategies>
        ): Sequence<List<Strategy<*>>> {
            val combiner = Combiner(correctHostname = correctHostname, fillerHostname = fillerHostname)
            val strategiesToIgnore = ignoredStrategies().toMutableSet()
            excludeStrategies.forEach { strategiesToIgnore.addAll(it.strategiesToRemove) }

            return combiner.getAllCombinations(testStrength, strategiesToIgnore.toSet())
        }

        /**
         * Holds strategies that are not used in combinations. I.e. these strategies always have their default instantiations
         */
        private fun ignoredStrategies(): List<Strategies> {
            return listOf(Strategies.EXTENSION)
        }
    }
}