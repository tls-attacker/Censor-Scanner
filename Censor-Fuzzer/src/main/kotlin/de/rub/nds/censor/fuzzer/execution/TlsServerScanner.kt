package de.rub.nds.censor.fuzzer.execution

import de.rub.nds.censor.core.connection.HttpsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.fuzzer.config.FuzzerConfig
import de.rub.nds.censor.core.data.ServerAddress
import de.rub.nds.censor.fuzzer.data.ServerEvaluation
import de.rub.nds.censor.fuzzer.data.TestVector
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage
import de.rub.nds.tlsattacker.core.http.header.LocationHeader
import kotlinx.coroutines.*
import kotlinx.serialization.ExperimentalSerializationApi
import me.tongfei.progressbar.ProgressBar
import org.apache.logging.log4j.kotlin.Logging
import kotlin.system.measureTimeMillis

/**
 * Scans a TLS server instantiation for their acceptance of invalid SNI mutations.
 */
class TlsServerScanner(
    override val fuzzerConfig: FuzzerConfig,
    override val serverEvaluation: ServerEvaluation,
    override val dispatcher: CoroutineDispatcher = Dispatchers.IO,
): Scanner() {

    /**
     * Evaluates all combinations on a TLS server. Executes a default connection to the server and checks whether
     * other combinations work similarly or break the connection attempt.
     */
    @OptIn(ExperimentalSerializationApi::class)
    override fun scanServer(
        server: ServerAddress,
        serverEvaluation: ServerEvaluation
    ) {

        // try to extract default http content of website
        val defaultHttpAnswer = try {
            getDefaultHttpContent(server)
        } catch (e: NotConnectableException) {
            // could not connect to server due to exception
            logger.warn("Skipping server $server because it is not connectable via HTTPS, encountered error $e")
            serverEvaluation.serverBehaviorOnControlVector = e.reason
            return
        }

        if (defaultHttpAnswer == null) {
            logger.warn("Skipping server $server because it did not return a HTTP answer")
            return
        }
        serverEvaluation.apply {
            defaultServerAnswerTitle = getTitleOfWebsite(defaultHttpAnswer.responseContent.value)
            serverEvaluation.serverBehaviorOnControlVector = ConnectionReturn.WORKING
        }

        defaultHttpAnswer.responseStatusCode.value.also {
            if (it != "200" && it != "200 OK") {
                logger.warn("Skipping server $server because it does not return HTTP 200. Instead it returned code $it with content:\n${defaultHttpAnswer.responseContent.value}")
                return
            }
        }

        logger.info("Executing test vectors in parallel!")
        val elapsed = measureTimeMillis {
            // enter the coroutine world here to execute each connection in parallel
            val progressBar = ProgressBar("Test Vectors", serverEvaluation.vectors.size.toLong())
            runBlocking {
                val scanTime = measureTimeMillis {
                    // evaluate each test vector in parallel
                    val deferredResults = serverEvaluation.vectors.shuffled().map { vector ->
                        async(dispatcher) {
                            evaluateTestVector(
                                    server,
                                    vector,
                                    defaultHttpAnswer
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

    /**
     * Returns the default HTTP response of the server on a TLS 1.2 connection with correct SNI.
     *
     * @throws NotConnectableException when the server is not connectable via TLS 1.2
     */
    @Throws(NotConnectableException::class)
    private fun getDefaultHttpContent(server: ServerAddress): HttpResponseMessage? {
        val httpsConnection = HttpsConnection(
            ip = server.ip,
            serverPort = server.port,
            timeout = timeout,
            censorScanType = CensorScanType.DIRECT,
            hostname = server.hostname,
            pcapCapturer = pcapCapturer,
            keyLogFilePath = fuzzerConfig.keyLogFile
        )
        httpsConnection.registerManipulations(SniExtensionManipulation(hostName = server.hostname, enable = true))
        runBlocking(dispatcher) {
            httpsConnection.connect()
        }
        return httpsConnection.firstHttpResponse
    }

    /**
     * Evaluates a test vector and applies the result to it.
     */
    private suspend fun evaluateTestVector(
        server: ServerAddress,
        vector: TestVector,
        defaultHttpAnswer: HttpResponseMessage
    ) {

        // connect to server with manipulations specified in test vector
        val connection = HttpsConnection(
            ip = server.ip,
            serverPort = server.port,
            timeout = timeout,
            censorScanType = CensorScanType.DIRECT,
            hostname = server.hostname,
            pcapCapturer = pcapCapturer,
            keyLogFilePath = fuzzerConfig.keyLogFile
        )
        connection.registerManipulations(vector.instantiatedStrategies.flatMap { it.getManipulations() })

        var workingType = ConnectionReturn.WORKING
        try {
            connection.connect()
        } catch (e: NotConnectableException) {
            // exception during TLS connection
            if (!e.reason.working()) {
                vector.apply {
                    result = e.reason
                    exception = e
                    if (e.reason == ConnectionReturn.INTERNAL_ERROR) {
                        logger.error("Internal error: $e")
                    }
                }
                return
            } else {
                workingType = e.reason
            }
        } finally {
            vector.apply { instantiatedStrategies.clear() }
        }

        // if the TLS connection went through, we can analyze for same http output here
        val httpAnswer = connection.firstHttpResponse
        // interpret result
        if (httpAnswer == null) {
            // no http answer
            vector.apply { result = ConnectionReturn.NO_HTTP }
        } else {
            if (httpResponsesAreEqual(defaultHttpAnswer, httpAnswer)) {
                // same behavior
                vector.apply { result = workingType }
            } else {
                // different behavior
                vector.apply { result = ConnectionReturn.DIFFERENT_HTTP }
            }
        }
    }

    /**
     * Checks whether two {@link HttpResponseMessage}s are equal.
     */
    private fun httpResponsesAreEqual(message1: HttpResponseMessage, message2: HttpResponseMessage): Boolean {
        // Save responseCode for further analysis and check for equality
        val responseCode = message1.responseStatusCode.value
        if (responseCode != message2.responseStatusCode.value) {
            return false
        }

        // for redirect status codes we check for the location header as well
        if (responseCode.startsWith("3")) {
            val locationHeader1 = message1.header.firstOrNull { header -> header is LocationHeader }
            val locationHeader2 = message2.header.firstOrNull { header -> header is LocationHeader }

            return if (locationHeader1 == null && locationHeader2 == null) {
                // wrong behavior, but nevertheless same behavior
                true
            } else if (locationHeader1 != null && locationHeader2 != null) {
                // both are present
                locationHeader1.headerValue.value == locationHeader2.headerValue.value
            } else {
                // only one is present
                false
            }
        }

        // For the OK status code we check whether a title is present in the html and check for equality
        if (responseCode.contains("200")) {
            val defaultTitle = getTitleOfWebsite(message2.responseContent.value)
            val receivedTitle = getTitleOfWebsite(message1.responseContent.value)
            return defaultTitle == receivedTitle
        }

        // other status codes indicate differentiating behavior
        return false
    }

    /**
     * Extracts the content of the title tag in the given html string. Does not do HTML parsing and
     * only searches for \<title></title>\> and \\>.
     *
     * @param html The html as a string.
     * @return Title of the webpage or null if none is present
     */
    private fun getTitleOfWebsite(html: String): String? {
        val titleStart = "<title"
        val titleEnd = "</title>"

        // both tags must be present for title extraction
        if (!(html.contains(titleStart) && html.contains(titleEnd))) {
            return null
        }
        val startIndex = html.indexOf(titleStart) + titleStart.length
        val endIndex = html.indexOf(titleEnd)
        return html.substring(startIndex, endIndex)
    }

    companion object : Logging
}