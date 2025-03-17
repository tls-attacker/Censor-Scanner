/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2023
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
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.connection.OutboundConnection
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration
import de.rub.nds.tlsattacker.core.state.State
import de.rub.nds.tlsattacker.core.workflow.DTLSWorkflowExecutor
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor
import de.rub.nds.tlsattacker.transport.TransportHandlerType
import de.rub.nds.tlsattacker.transport.udp.UdpTransportHandler

/** Implements a DTLS 1.2 connection using TLS-Attacker.  */
// TODO: currently does not extend UDP connection
class DtlsConnection(
    ip: IpAddress,
    serverPort: Int,
    timeout: Int,
    censorScanType: CensorScanType,
    clientPort: Int = -1,
    pcapCapturer: PcapCapturer? = null,
    keyLogFilePath: String = "",
    hostname: String? = null,
) :
    BasicTlsConnection(ip, serverPort, timeout, censorScanType, clientPort, pcapCapturer, keyLogFilePath, hostname) {

    override fun generateConfig(): Config {
        // set config values
        val tlsConfig = super.generateConfig()
        tlsConfig.defaultSelectedProtocolVersion = ProtocolVersion.DTLS12
        tlsConfig.supportedVersions = listOf(ProtocolVersion.DTLS12)
        tlsConfig.defaultLayerConfiguration = StackConfiguration.DTLS
        return tlsConfig
    }

    override fun generateOutboundConnection(): OutboundConnection {
        val outboundConnection = super.generateOutboundConnection()
        outboundConnection.transportHandlerType = TransportHandlerType.UDP
        outboundConnection.hostname = ip.address
        return outboundConnection
    }

    /**
     * Extracts the connection details from the underlying socket.
     */
    override fun extractConnectionTuple(state: State): ConnectionTuple {
        val transportHandler = state.tlsContext.transportHandler as UdpTransportHandler
        return ConnectionTuple(
            transportHandler.srcIp,
            transportHandler.srcPort,
            transportHandler.dstIp,
            transportHandler.dstPort,
            false
        )
    }

    override fun setWorkflowExecutor(state: State): WorkflowExecutor {
        return DTLSWorkflowExecutor(state)
    }

    @Throws(NotConnectableException::class)
    override fun createAndBindSocket(executor: WorkflowExecutor, state: State) {
        try {
            executor.initTransportHandler(state)
        } catch (e: Exception) {
            throw NotConnectableException(ConnectionReturn.INTERNAL_ERROR, e)
        }
    }

    override fun connectSocket(state: State) {
        // nothing to do
    }

    override val identifier: String
        /** Returns information about the manipulations registered on this connection  */
        get() = (listOf("DTLS") + manipulations.map { it.name }).joinToString(":")
}