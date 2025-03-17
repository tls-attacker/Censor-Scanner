package de.rub.nds.censor.core.connection

import de.rub.nds.censor.core.connection.manipulation.Manipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.network.ConnectionTuple
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.core.util.Util
import java.net.DatagramSocket
import java.net.Socket

sealed class UdpConnection(
    ip: IpAddress,
    serverPort: Int,
    timeout: Int,
    clientPort: Int = -1,
    pcapCapturer: PcapCapturer? = null
) : PortBoundConnection<Manipulation>(ip, serverPort, timeout, clientPort, pcapCapturer) {

    override fun analyzeCancelledConnection(
        connectionTuple: ConnectionTuple?,
        exception: NotConnectableException,
        enableLog: Boolean,
        pcapCapturer: PcapCapturer?
    ): NotConnectableException {
        if (exception.reason != ConnectionReturn.ANALYZE_FURTHER || connectionTuple == null || pcapCapturer == null) {
            // cant analyze further
            return exception
        } else {
            val queue = pcapCapturer.getUdpQueue(connectionTuple)
            if (queue == null) {
                // cant analyze further
                if (enableLog) {
                    logger.error("Queue for $connectionTuple not registered")
                }
                return NotConnectableException(ConnectionReturn.INTERNAL_ERROR)
            }
            if (queue.isEmpty()) {
                // cant analyze further
                if (enableLog) {
                    logger.error("Queue for $connectionTuple is empty while trying to analyze it. This is an indicator for a too short waiting time!")
                }
                return NotConnectableException(ConnectionReturn.INTERNAL_ERROR)
            }
            //TODO: Meaningful analysis for DTLS
            throw NotConnectableException(ConnectionReturn.UNKNOWN)
        }
    }

    /**
     * Extracts the connection details from the underlying UDP socket.
     */
    fun extractConnectionTupleFromUdpSocket(socket: DatagramSocket): ConnectionTuple {
        return ConnectionTuple(
            Util.getSrcIp(ip),
            socket.localPort,
            ip.address,
            serverPort,
            true
        )
    }
}