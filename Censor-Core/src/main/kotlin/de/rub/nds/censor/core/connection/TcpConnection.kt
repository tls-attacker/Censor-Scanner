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

import de.rub.nds.censor.core.connection.manipulation.Manipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.network.ConnectionTuple
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.core.util.Util
import java.net.InetSocketAddress
import java.net.Socket

/** Checks whether a server is reachable via TCP over any client port.  */
sealed class TcpConnection<Manipulation>(
    ip: IpAddress,
    serverPort: Int,
    timeout: Int,
    clientPort: Int = -1,
    pcapCapturer: PcapCapturer? = null
) : PortBoundConnection<Manipulation>(ip, serverPort, timeout, clientPort, pcapCapturer) {

    /**
     * Create own TCP socket to server and bind to free local port.
     */
    fun createAndBindTcpSocket(): Socket {
        return Socket().also {
            it.reuseAddress = true
            it.soTimeout = timeout
            // 2^16 max record size
            it.sendBufferSize = 65536
            // bind to some local port
            if (clientPort != -1) {
                it.bind(InetSocketAddress(clientPort))
            } else {
                it.bind(null)
            }
        }
    }

    /**
     * Extracts the connection details from the underlying TCP socket.
     */
    fun extractConnectionTupleFromTcpSocket(socket: Socket): ConnectionTuple {
        return ConnectionTuple(
            Util.getSrcIp(ip),
            socket.localPort,
            ip.address,
            serverPort,
            true
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun analyzeCancelledConnection(
        connectionTuple: ConnectionTuple?,
        exception: NotConnectableException,
        enableLog: Boolean,
        pcapCapturer: PcapCapturer?
    ): NotConnectableException {
        if ((exception.reason != ConnectionReturn.ANALYZE_FURTHER && exception.reason != ConnectionReturn.UNKNOWN) || connectionTuple == null || pcapCapturer == null) {
            // cant analyze further
            return exception
        } else {
            val queue = pcapCapturer.getTcpQueue(connectionTuple)
            if (queue == null) {
                // cant analyze further
                if (enableLog) {
                    logger.error("Queue for $connectionTuple not registered")
                }
                return NotConnectableException(ConnectionReturn.UNKNOWN)
            }
            if (queue.isEmpty()) {
                // cant analyze further
                if (enableLog && exception.reason == ConnectionReturn.UNKNOWN) { // only print in 2nd iteration
                    logger.error("Queue for $connectionTuple is empty while trying to analyze it. This is an indicator for a too short waiting time!")
                }
                return NotConnectableException(ConnectionReturn.UNKNOWN)
            }

            // count received RST packets
            return when (queue.count { packet ->  packet.header.rst && packet.header.srcPort.value()?.toInt() == connectionTuple.port2}) {
                0 -> {
                    // HTTP Bad Request in payload
                    if (queue.any { it.payload != null && it.payload.rawData != null && "485454502f312e31203430302042616420526571756573740d0a" in it.payload.rawData.toHexString() }) return NotConnectableException(
                        ConnectionReturn.BAD_REQUEST)
                    // no packet from server with payload
                    if (!queue.any{ packet -> packet.header.srcPort.value()?.toInt() == connectionTuple.port2 && packet.payload != null} ) return NotConnectableException(
                        ConnectionReturn.NO_SERVER_ANSWER)
                    // not able to determine reason
                    return NotConnectableException(ConnectionReturn.UNKNOWN)
                }
                1 -> NotConnectableException(ConnectionReturn.TCP_RESET)
                2 -> NotConnectableException(ConnectionReturn.TCP_RESET_TWO)
                3 -> NotConnectableException(ConnectionReturn.TCP_RESET_THREE)
                else -> NotConnectableException(ConnectionReturn.TCP_RESET_MANY)
            }
        }
    }



    override val name: String
        get() = "TCP/" + super.name
}