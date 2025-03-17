package de.rub.nds.censor.core.connection

import de.rub.nds.censor.core.connection.manipulation.Manipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.exception.PcapException
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import java.io.IOException
import java.net.BindException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Sends test data to a server and checks whether the same answer (for echo) or if expected answer (for simple) is returned.
 * Shares a lot of code with EchoTlsConnection and BasicTlsConnection.
 */
class TcpDataConnection(
    ip: IpAddress,
    serverPort: Int,
    timeout: Int,
    clientPort: Int = -1,
    pcapCapturer: PcapCapturer? = null,
    private val echo: Boolean = true,
    private val data: ByteArray,
    private val simpleScanAnswerBytes: ByteArray = byteArrayOf(65, 65, 65, 65, 65)
) : TcpConnection<Manipulation>(ip, serverPort, timeout, clientPort, pcapCapturer) {

    /**
     * Sends test data to aserver and check whether it returns the expected bytes.
     */
    override suspend fun connect() {
        // try to open TCP socket
        var socket: Socket
        while (true) {
            try {
                socket = createAndBindTcpSocket() // necessary because of resource exhaustion
                break
            } catch (e: BindException) {
                logger.debug("Could not bind socket for TCP data connection on port ${clientPort}... sleeping")
                Thread.sleep(500)
            }
        }

        clientPort = socket.localPort
        connectionTuple = extractConnectionTupleFromTcpSocket(socket)

        while (true) {
            try {
                pcapCapturer?.register(connectionTuple!!)
            } catch (e: PcapException) {
                Thread.sleep(200)
                continue
            }
            logger.debug("Registered PcapCapturer for $connectionTuple")
            break
        }

        try {
            socket.connect(InetSocketAddress(ip.address, serverPort), timeout)
        } catch (e: SocketTimeoutException) {
            logger.warn("TCP socket timed out!")
            socket.close()
            connectionTuple?.also { tuple -> pcapCapturer?.deregister(tuple) }
            throw NotConnectableException(ConnectionReturn.TIMEOUT, e)
        } catch (e: IOException) {
            logger.warn("Could not connect to socket" + e.stackTraceToString())
            socket.close()
            connectionTuple?.also { tuple -> pcapCapturer?.deregister(tuple) }
            throw NotConnectableException(ConnectionReturn.UNREACHABLE, e)
        }

        try {
            // send test data
            logger.debug("Sending data..." + data.toString(Charsets.ISO_8859_1))
            try {
                socket.getOutputStream().write(data)
            } catch (e: IOException) {
                logger.debug("Could not send data: " + e.stackTraceToString())
                throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER, e)
            }

            // check same data for Echo
            if (echo) {
                val receivedBytes = try {
                    socket.getInputStream().readNBytes(data.size)
                } catch (exception: IOException) {
                    throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER)
                }
                if (data.size < receivedBytes.size) {
                    throw NotConnectableException(
                        ConnectionReturn.INTERNAL_ERROR,
                        "Received too many bytes on ECHO request."
                    )
                } else if (data.size > receivedBytes.size) {
                    throw NotConnectableException(
                        ConnectionReturn.LESS_DATA,
                        "Received less bytes than expected on ECHO request."
                    )
                } else if (!data.contentEquals(receivedBytes)) {
                    throw NotConnectableException(
                        ConnectionReturn.DIFFERENT_DATA,
                        "Received different bytes than sent in ECHO request."
                    )
                }
            } else {
                logger.debug("Non-Echo case")
                // receive simple expected data
                val receivedBytes = try {
                    socket.getInputStream().readNBytes(simpleScanAnswerBytes.size)
                } catch (exception: IOException) {
                    logger.debug("Could not receive bytes")
                    logger.debug(exception.stackTraceToString())
                    throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER)
                }
                if (!simpleScanAnswerBytes.contentEquals(receivedBytes)) {
                    logger.debug("Received: " + receivedBytes.toString(Charsets.ISO_8859_1))
                    throw NotConnectableException(
                        ConnectionReturn.DIFFERENT_DATA,
                        "Received different bytes than expected."
                    )
                }
            }
        } catch (e: NotConnectableException) {
            // keep blocking
            Thread.sleep(1000)
            // further analyze why we could not connect and throw the more detailed exception
            try {
                analyzeCancelledConnection(connectionTuple, e, false, pcapCapturer)
                    .also { logger.debug(it) }
                    .also { throw it }
            } catch (e: NotConnectableException) {
                if (e.reason == ConnectionReturn.UNKNOWN) {
                    logger.debug("Unknown analysis - waiting additional 5 seconds for more packets to arrive")
                    // keep blocking
                    Thread.sleep(5000)
                    analyzeCancelledConnection(connectionTuple, e, true, pcapCapturer)
                        .also { logger.debug(it) }
                        .also { throw it }
                } else {
                    throw e
                }
            }
        } catch (e: Exception) {
            logger.error("Internal error in connection attempt to $this with exception: ", e)
            throw NotConnectableException(ConnectionReturn.INTERNAL_ERROR)
        } finally {
            socket.close()
            connectionTuple?.also { tuple -> pcapCapturer?.deregister(tuple) }
        }
    }
}