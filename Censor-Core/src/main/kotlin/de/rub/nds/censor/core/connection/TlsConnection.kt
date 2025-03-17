/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2017-2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection

import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.network.ConnectionTuple
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.core.util.Util
import de.rub.nds.tlsattacker.core.state.State
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor
import de.rub.nds.tlsattacker.transport.tcp.TcpTransportHandler
import java.io.IOException
import java.net.SocketTimeoutException

/** Implements a TLS1.2 connection using TlsAttacker.  */
open class TlsConnection(
    ip: IpAddress,
    serverPort: Int,
    timeout: Int,
    censorScanType: CensorScanType,
    clientPort: Int = -1,
    pcapCapturer: PcapCapturer? = null,
    keyLogFilePath: String = "",
    hostname: String? = null,
    simpleScanAnswerBytes: ByteArray = byteArrayOf(65, 65, 65, 65, 65)
) : BasicTlsConnection(ip, serverPort, timeout, censorScanType, clientPort, pcapCapturer, keyLogFilePath, hostname, simpleScanAnswerBytes) {

    /**
     * Extracts the connection details from the underlying socket.
     */
    override fun extractConnectionTuple(state: State): ConnectionTuple {
        val transportHandler = state.tlsContext.transportHandler as TcpTransportHandler
        return ConnectionTuple(
            Util.getSrcIp(ip),
            transportHandler.srcPort,
            ip.address,
            transportHandler.dstPort,
            true
        )
    }

    override fun setWorkflowExecutor(state: State): WorkflowExecutor {
        return DefaultWorkflowExecutor(state)
    }

    @Throws(NotConnectableException::class)
    override fun createAndBindSocket(executor: WorkflowExecutor, state: State) {
        try {
            val transportHandler = EarlyBindTcpTransportHandler(state.context.connection)
            transportHandler.isResetClientSourcePort = true
            transportHandler.isRetryFailedSocketInitialization = true
            transportHandler.createSocket()
            state.context.transportHandler = transportHandler
        } catch (e: IOException) {
            throw NotConnectableException(ConnectionReturn.INTERNAL_ERROR, e)
        }
    }

    @Throws(NotConnectableException::class)
    override fun connectSocket(state: State) {
        try {
            (state.context.transportHandler as EarlyBindTcpTransportHandler).connectSocket()
        } catch (e: SocketTimeoutException) {
            logger.warn("Socket timed out in TLS connection!")
            throw NotConnectableException(ConnectionReturn.TIMEOUT, e)
        } catch (e: IOException) {
            throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER, e)
        }
    }

    override val identifier: String
        /** Returns information about the manipulations registered on this connection  */
        get() = (listOf("TLS") + manipulations.map { it.name }).joinToString(":")
}