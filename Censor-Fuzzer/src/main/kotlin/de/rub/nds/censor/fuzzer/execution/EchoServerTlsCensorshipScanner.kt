package de.rub.nds.censor.fuzzer.execution

import de.rub.nds.censor.core.connection.EchoTlsConnection
import de.rub.nds.censor.core.connection.TcpDataConnection
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.fuzzer.config.FuzzerConfig
import de.rub.nds.censor.core.data.ServerAddress
import de.rub.nds.censor.fuzzer.data.ServerEvaluation
import de.rub.nds.censor.fuzzer.data.TestVector
import kotlinx.coroutines.*
import kotlinx.serialization.ExperimentalSerializationApi
import me.tongfei.progressbar.ProgressBar
import org.apache.logging.log4j.kotlin.Logging
import kotlin.system.measureTimeMillis

/**
 * Scans an ECHO server for its acceptance of different TLS ClientHello messages.
 */
class EchoServerTlsCensorshipScanner(
    override val fuzzerConfig: FuzzerConfig,
    override val serverEvaluation: ServerEvaluation,
    override val dispatcher: CoroutineDispatcher = Dispatchers.IO,
): Scanner() {

    @OptIn(ExperimentalStdlibApi::class)
    val echoTestData = "32f400300f55".hexToByteArray()

    @OptIn(ExperimentalSerializationApi::class, ExperimentalStdlibApi::class)
    override fun scanServer(server: ServerAddress, serverEvaluation: ServerEvaluation) {

        // check if server is reachable
        isReachable(server).also {
            if (it != ConnectionReturn.WORKING) {
                logger.info("ECHO server did not return echo test data ${echoTestData.toHexString()} because of $it")
                return
            }
        }

        // check behavior on default SNI
        getDefaultSniAnswer(serverEvaluation.server).also {
            logger.info("Default server behavior on SNI is $it")
            serverEvaluation.serverBehaviorOnControlVector = it
        }

        // TODO: refactor out
        logger.info("Executing test vectors in parallel!")

        val elapsed = measureTimeMillis {
            // enter the coroutine world here to execute each connection in parallel
            val progressBar = ProgressBar("Test Vectors", serverEvaluation.vectors.size.toLong())
            runBlocking {
                val scanTime = measureTimeMillis {
                    // evaluate each test vector in parallel
                    val deferredResults = serverEvaluation.vectors.map { vector ->
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
        }
        logger.info("Scan took ${elapsed / 1000} seconds")
    }

    private fun isReachable(server: ServerAddress): ConnectionReturn {
        TcpDataConnection(server.ip,
            server.port,
            timeout,
            pcapCapturer = pcapCapturer,
            data = echoTestData).also { tcpEchoConnection ->
                return runBlocking {
                    try {
                        tcpEchoConnection.connect()
                        ConnectionReturn.WORKING
                    } catch (exception: NotConnectableException) {
                        exception.reason
                    }
                }
        }
    }

    private fun getDefaultSniAnswer(server: ServerAddress): ConnectionReturn {
        val connection = EchoTlsConnection(
            ip = server.ip,
            serverPort = server.port,
            timeout = timeout,
            hostname = server.hostname,
            pcapCapturer = pcapCapturer,
            keyLogFilePath = fuzzerConfig.keyLogFile
        )
        connection.registerManipulations(SniExtensionManipulation(hostName = server.hostname, enable = true))
        return runBlocking(dispatcher) {
            try {
                connection.connect()
                ConnectionReturn.WORKING
            } catch (exception: NotConnectableException) {
                exception.reason
            }
        }

    }

    private suspend fun evaluateTestVector(
        server: ServerAddress,
        vector: TestVector) {
        // connect to server with manipulations specified in test vector
        val connection = EchoTlsConnection(
            ip = server.ip,
            serverPort = server.port,
            timeout = timeout,
            hostname = server.hostname,
            pcapCapturer = pcapCapturer,
            keyLogFilePath = fuzzerConfig.keyLogFile
        )
        connection.registerManipulations(vector.instantiatedStrategies.flatMap { it.getManipulations() })

        try {
            connection.connect()
        } catch (e: NotConnectableException) {
            // exception during TLS connection
            if (!e.reason.working()) {
                vector.apply {
                    result = e.reason
                    exception = e
                }
                return
            } else {
                vector.apply { e.reason }
            }
        }
        vector.apply { result = ConnectionReturn.WORKING }
    }

    companion object : Logging
}