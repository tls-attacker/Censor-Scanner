package de.rub.nds.censor.fuzzer.execution

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.constants.Censor
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.data.ServerAddress
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.fuzzer.config.FuzzerConfig
import de.rub.nds.censor.fuzzer.constants.CensorshipValues
import de.rub.nds.censor.fuzzer.data.ServerEvaluation
import de.rub.nds.censor.fuzzer.data.TestVector
import de.rub.nds.censor.fuzzer.execution.port.ChinaPortProvider
import kotlinx.coroutines.*
import kotlinx.serialization.ExperimentalSerializationApi
import me.tongfei.progressbar.ProgressBar
import org.apache.logging.log4j.kotlin.Logging
import kotlin.coroutines.coroutineContext
import kotlin.system.measureTimeMillis

class SimpleTlsCensorshipScanner(
    override val dispatcher: CoroutineDispatcher,
    override val fuzzerConfig: FuzzerConfig,
    override val serverEvaluation: ServerEvaluation,
    // used for censorship determination
    private val censor: Censor = Censor.CHINA
) : Scanner() {

    // selects the server ports to connect to
    private var portProvider: ChinaPortProvider? = if(censor == Censor.CHINA) {
        ChinaPortProvider()
    } else {
        null
    }

    override fun scanServer(server: ServerAddress, serverEvaluation: ServerEvaluation) {
        runBlocking(dispatcher) {
            portProvider?.initialize()
            // check if default vector is censored, if not skip
            val defaultBehavior: ConnectionReturn = try {
                // also try multiple times
                evaluateGroundTruth(server)
            } catch (e: Exception) {
                // could not connect to server due to exception
                logger.warn("Skipping server $server because initial connection attempt encountered error $e")
                serverEvaluation.serverBehaviorOnControlVector = ConnectionReturn.INTERNAL_ERROR
                return@runBlocking
            }

            if (!defaultBehavior.indicatesSniCensorship(censor)) {
                logger.warn("Skipping server $server because it does not seem to censor")
                return@runBlocking
            }

            serverEvaluation.apply {
                serverEvaluation.serverBehaviorOnControlVector = defaultBehavior
            }

            logger.info("Executing test vectors in parallel!")
            val elapsed = measureTimeMillis {
            val progressBar = ProgressBar("Test Vectors", serverEvaluation.vectors.size.toLong())
                val scanTime = measureTimeMillis {
                    // evaluate each test vector in parallel
                        val deferredResults = serverEvaluation.vectors.filter { it.result != ConnectionReturn.UNSET}. shuffled().map { vector ->
                        async(dispatcher) {
                            evaluateTestVector(
                                server,
                                vector
                            )
                        }.also { it.invokeOnCompletion { progressBar.step() } }
                    }
                    // await completion of all test vectors
                    deferredResults.toList().awaitAll()
                    // finish progress bar, and persist results
                    progressBar.stepTo(progressBar.max)
                    progressBar.close()
                    serverEvaluation.encodeToStream("${fuzzerConfig.outputFileIdentifier}_vectors.json", true)
                }

                ResultAnalyzer(
                    serverEvaluation,
                    fuzzerConfig,
                    scanTime
                ).interpretResults()
            }
            logger.info("Scan took ${elapsed / 60000} minutes")
        }
    }

    private suspend fun evaluateGroundTruth(server: ServerAddress): ConnectionReturn {
        val port = portProvider?.getPort() ?: server.port
        val connection = TlsConnection(server.ip, port, fuzzerConfig.timeout, CensorScanType.SIMPLE, pcapCapturer = pcapCapturer, hostname = fuzzerConfig.hostname, simpleScanAnswerBytes = fuzzerConfig.simpleScanServerAnswerBytes.toByteArray())
        connection.registerManipulations(SniExtensionManipulation(fuzzerConfig.hostname, true))
        return try {
            connection.connect()
            portProvider?.releaseUncensoredPort(port)
            ConnectionReturn.WORKING
        } catch (e: NotConnectableException) {
            e.reason
        }
    }

    /**
     * Attempts MAX_TRIES many connections for this test vector. Ignores TIMEOUTS up to a specific amount
     */
    private suspend fun evaluateTestVector(server: ServerAddress, vector: TestVector) {
        val results = mutableListOf<ConnectionReturn>()
        var tries = 0
        var timeouts = 0

        while (true) {
            if (timeouts >= CensorshipValues.MAX_TIMEOUT_TRIES) {
                // cancel with timeout
                vector.result = ConnectionReturn.TIMEOUT
                return
            }
            val aggregatedResult = getAggregatedResult(results)
            if (tries >= CensorshipValues.INITIAL_TRIES && aggregatedResult != ConnectionReturn.UNDECIDED) {
                // found a result
                vector.result = aggregatedResult
                return
            }
            if (tries >= CensorshipValues.MAX_TRIES) {
                vector.result = ConnectionReturn.UNDECIDED
                return
            }
            // else continue scanning
            val result = getAnswerOfServer(server, vector)
            if (result == ConnectionReturn.TIMEOUT) {
                timeouts++
            } else {
                results.add(result)
                tries++
            }
        }
    }

    private fun getAggregatedResult(results: List<ConnectionReturn>): ConnectionReturn {
        val total = results.size
        ConnectionReturn.entries.filter { it != ConnectionReturn.NO_SERVER_ANSWER } .forEach { entry ->
            if (results.count { it == entry } >= total * CensorshipValues.DECISION_BARRIER) {
                return entry
            }
        }
        return ConnectionReturn.UNDECIDED
    }

    private suspend fun getAnswerOfServer(server: ServerAddress, vector: TestVector): ConnectionReturn {
        val port = portProvider?.getPort() ?: server.port
        val connection = TlsConnection(server.ip, port, fuzzerConfig.timeout, CensorScanType.SIMPLE, pcapCapturer = pcapCapturer, hostname = fuzzerConfig.hostname)
        connection.registerManipulations(vector.instantiatedStrategies.flatMap { it.getManipulations() })
        return try {
            connection.connect()
            portProvider?.releaseUncensoredPort(port)
            ConnectionReturn.WORKING
        } catch (e: NotConnectableException) {
            CoroutineScope(coroutineContext).launch {
                portProvider?.releaseCensoredPort(port)
            }
            if (e.reason.indicatesSniCensorship(censor)) {
                ConnectionReturn.CENSORED
            } else {
                e.reason
            }
        }
    }

    companion object : Logging
}