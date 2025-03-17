package de.rub.nds.censor.core.util

import kotlinx.coroutines.*
import org.apache.logging.log4j.kotlin.Logging
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import kotlin.coroutines.coroutineContext

/**
 * ECHO server that can be used for testing purposes.
 */
class EchoServer(var port: Int = -1, private val dispatcher: CoroutineDispatcher = Dispatchers.IO) {

    suspend fun run() {

        // create server socket
        val serverSocket = if (port >= 0) {
            withContext(dispatcher) {
                ServerSocket(port)
            }
        } else {
            withContext(dispatcher) {
                ServerSocket()
            }
        }
        withContext(dispatcher) {
            serverSocket.bind(null)
        }
        serverSocket.soTimeout = 1000
        port = serverSocket.localPort
        logger.debug("Started ECHO server on port $port")

        try {
            // accept client connections
            while (true) {
                // allow for cancellation
                yield()
                val clientSocket = try {
                    withContext(dispatcher) {
                        serverSocket.accept()
                    }
                } catch (_: SocketTimeoutException) {
                    // the server regularly timeouts on accepts to yield() for cancellation and resumes accepting if
                    // not cancelled
                    continue
                } catch (_: SocketException) {
                    continue
                }
                // launch and forget client connection
                with(CoroutineScope(coroutineContext)) {
                    launch(dispatcher) {
                        try {
                            handleConnection(clientSocket)
                        } catch (e: Exception) {
                            logger.warn("Exception during connection handling: $e")
                        }
                    }
                }
            }
        } catch (e: CancellationException) {
            logger.debug("Cancelled server socket! $e")
            return
        } catch (e: Exception) {
            logger.warn("Server socket cancelled with exception: ", e)
            return
        }
    }

    private suspend fun handleConnection(clientSocket: Socket) {
        val readStream = withContext(dispatcher) {
            clientSocket.getInputStream()
        }
        val sendStream = withContext(dispatcher) {
            clientSocket.getOutputStream()
        }
        // echo all received bytes
        withContext(dispatcher) {
            while (true) {
                val buffer = ByteArray(1024)
                val readBytes = readStream.read(buffer)
                if (readBytes == -1) {
                    return@withContext
                }
                sendStream.write(buffer.copyOfRange(0, readBytes))
            }
        }
    }

    companion object : Logging
}