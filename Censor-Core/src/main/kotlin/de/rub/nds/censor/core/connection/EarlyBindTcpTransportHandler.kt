package de.rub.nds.censor.core.connection

import de.rub.nds.censor.core.config.GeneralDelegate.Companion.logger
import de.rub.nds.tlsattacker.transport.Connection
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler
import java.io.IOException
import java.io.PushbackInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

class EarlyBindTcpTransportHandler(connection: Connection): ClientTcpTransportHandler(connection) {

    init {
        srcPort = connection.sourcePort
    }

    @Throws(IOException::class)
    fun createSocket(): Socket {
        val timeoutTime = System.currentTimeMillis() + connectionTimeout
        var lastException: Exception? = null
        while (System.currentTimeMillis() < timeoutTime) {
            try {
                socket = Socket()
                socket.reuseAddress = true
                // reuse client port only when present and either retried socket initializations are
                // enabled or
                // client port has been manually set and the resetClientSourcePort setting is
                // disabled
                if (srcPort != null) {
                    socket.bind(InetSocketAddress(srcPort))
                } else {
                    socket.bind(null)
                    srcPort = socket.localPort
                }
                return socket
            } catch (e: Exception) {
                lastException = e
                try {
                    Thread.sleep(1000)
                } catch (ignore: Exception) {
                }
            }
        }
        if (lastException != null) {
            throw IOException(
                "Could not create socket or bind to client port ("
                        + srcPort
                        + ") with exception:",
                lastException
            )
        } else {
            throw IOException("Timed out on socket creation or port binding ($srcPort)")
        }
    }

    @Throws(IOException::class, SocketTimeoutException::class)
    fun connectSocket() {
        socket.connect(InetSocketAddress(hostname, dstPort), connectionTimeout.toInt())
        if (!socket.isConnected) {
            throw IOException("Could not connect to $hostname:$dstPort")
        }
        cachedSocketState = null
        setStreams(PushbackInputStream(socket.getInputStream()), socket.getOutputStream())
        srcPort = socket.localPort
        dstPort = socket.port
        logger.debug("Connection established from ports $srcPort -> $dstPort")
        socket.soTimeout = timeout.toInt()
        // 2^16 max record size
        socket.sendBufferSize = 65536
    }
}