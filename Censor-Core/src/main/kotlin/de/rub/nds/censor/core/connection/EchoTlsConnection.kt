package de.rub.nds.censor.core.connection

import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.network.ConnectionTuple
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.tlsattacker.core.state.State
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor
import de.rub.nds.tlsattacker.core.workflow.action.SendAction
import java.io.IOException
import java.net.BindException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

class EchoTlsConnection(ip: IpAddress,
                        serverPort: Int,
                        timeout: Int,
                        clientPort: Int = -1,
                        pcapCapturer: PcapCapturer? = null,
                        keyLogFilePath: String = "",
                        hostname: String? = null
) : TlsConnection(ip, serverPort, timeout, CensorScanType.ECHO, clientPort, pcapCapturer, keyLogFilePath, hostname) {

    private lateinit var socket: Socket
    /**
     * Does not set the WorkflowTrace executor and the outbound connection
     */
    override fun initializeConnectionParameters() {
        logger.debug("Preparing $name")
        tlsConfig = generateConfig()

        afterConfigInitCallbacks(tlsConfig)

        workflowTrace = generateWorkflowTrace()
        afterWorkflowTraceCallbacks(workflowTrace)

        state = generateState(tlsConfig, workflowTrace)
        afterStateGenerationCallback(state)
        // unnecessary but prevents lateinit var exception
        executor = setWorkflowExecutor(state)
    }

    /**
     * Create own TCP socket to server and bind to free local port.
     */
    override fun createAndBindSocket(executor: WorkflowExecutor, state: State) {
        // try to open TCP socket
        while(true) {
            try {
                socket = createAndBindTcpSocket() // necessary because of resource exhaustion
                return
            } catch (e: BindException) {
                logger.debug("Could not bind socket for TLS Echo connection... sleeping")
                Thread.sleep(500)
            }
        }
    }

    /**
     * Extracts the connection details from the underlying socket.
     */
    override fun extractConnectionTuple(state: State): ConnectionTuple {
        return extractConnectionTupleFromTcpSocket(socket)
    }

    @Throws(NotConnectableException::class)
    override fun connectSocket(state: State) {
        try {
            socket.connect(InetSocketAddress(ip.address, serverPort), timeout)
        } catch (e: SocketTimeoutException) {
            logger.warn("Socket timed out in Echo TLS connection!")
            throw NotConnectableException(ConnectionReturn.TIMEOUT, e)
        } catch (e: IOException) {
            throw NotConnectableException(ConnectionReturn.UNREACHABLE, e)
        }
    }

    /**
     * Sends the raw bytes of the serialized ClientHello TLSRecords over the opened TCP socket. Expects to receive the
     * same bytes in return.
     *
     * @return True, if the server echoes the bytes of the ClientHello message.
     */
    @Throws(NotConnectableException::class)
    override fun finalizeConnectionAttempt(state: State) {

        val action = workflowTrace.messageActions.filterIsInstance<SendAction>().getOrNull(0)

        if (action == null || action.configuredRecords.isEmpty() || action.configuredRecords.count { it == null } > 0) {
            throw NotConnectableException(
                ConnectionReturn.INTERNAL_ERROR,
                "Could not find configured records in first SendAction"
            )
        }

        val readStream = socket.getInputStream()
        val writeStream = socket.getOutputStream()
        // concatenate all records
        val completeRecordBytes = action.configuredRecords
            .map { it.completeRecordBytes.value }
            .reduce { acc, record -> acc + record }
        // send all configured records
        try {
            writeStream.write(completeRecordBytes)
        } catch (e: IOException) {
            throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER, e)
        }

        val receivedBytes = try {
            readStream.readNBytes(completeRecordBytes.size)
        } catch (exception: IOException) {
            throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER)
        }

        if (completeRecordBytes.size < receivedBytes.size) {
            throw NotConnectableException(ConnectionReturn.INTERNAL_ERROR, "Received too many bytes on ECHO request.")
        } else if (completeRecordBytes.size > receivedBytes.size) {
            throw NotConnectableException(ConnectionReturn.LESS_DATA, "Received less bytes than expected on ECHO request.")
        } else if (!completeRecordBytes.contentEquals(receivedBytes)) {
            throw NotConnectableException(ConnectionReturn.DIFFERENT_DATA, "Received different bytes than sent in ECHO request.")
        }
    }
}