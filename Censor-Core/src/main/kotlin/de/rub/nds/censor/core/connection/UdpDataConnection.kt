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

import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.exception.PcapException
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.BindException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

class UdpDataConnection(
    ip: IpAddress,
    serverPort: Int,
    timeout: Int,
    clientPort: Int = -1,
    pcapCapturer: PcapCapturer? = null,
    private val echo: Boolean = true,
    private val data: ByteArray,
    private val simpleScanAnswerBytes: ByteArray = byteArrayOf(65, 65, 65, 65, 65)
) :
    UdpConnection(ip, serverPort, timeout, clientPort, pcapCapturer = pcapCapturer) {

    /**
     * Sends 10 bytes to the server and waits for any answer. Does not reliably determine whether a server is running.
     */
    @Throws(NotConnectableException::class)
    override suspend fun connect() {
        var datagramSocket: DatagramSocket
        while (true) {
            try {
                if (clientPort == -1) {
                    datagramSocket = withContext(Dispatchers.IO) {
                        DatagramSocket()
                    }
                } else {
                    datagramSocket = withContext(Dispatchers.IO) {
                        DatagramSocket(clientPort)
                    }
                } // necessary because of resource exhaustion
                break
            } catch (e: BindException) {
                logger.debug("Could not bind socket for UDP data connection on port ${clientPort}... sleeping")
                Thread.sleep(500)
            }
        }

        connectionTuple = extractConnectionTupleFromUdpSocket(datagramSocket)

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
            datagramSocket.use { socket ->
                // send datagram with given data
                val byteBuffer = data
                val datagramLength = byteBuffer.size
                val packet = DatagramPacket(
                    byteBuffer,
                    datagramLength,
                    InetAddress.getByName(ip.address),
                    serverPort
                )
                socket.soTimeout = timeout
                socket.send(packet)
                try {
                    // receive datagram and check content
                    if (echo) {
                        val byteBufferReceive = ByteArray(datagramLength)
                        val packetReceive = DatagramPacket(byteBufferReceive, datagramLength)
                        socket.receive(packetReceive)
                        if (packetReceive.data == null) {
                            socket.close()
                            throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER)
                        } else if (!packetReceive.data.contentEquals(packet.data)) {
                            socket.close()
                            throw NotConnectableException(ConnectionReturn.DIFFERENT_DATA)
                        } else {
                            socket.close()
                            return
                        }
                    } else {
                        val byteBufferReceive = ByteArray(simpleScanAnswerBytes.size)
                        val packetReceive = DatagramPacket(byteBufferReceive, simpleScanAnswerBytes.size)
                        socket.receive(packetReceive)
                        if (packetReceive.data == null) {
                            socket.close()
                            throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER)
                        } else if (!packetReceive.data.contentEquals(simpleScanAnswerBytes)) {
                            socket.close()
                            throw NotConnectableException(ConnectionReturn.DIFFERENT_DATA)
                        } else {
                            socket.close()
                            return
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
        } catch (e: IOException) {
            logger.warn("Server seems to be unreachable with: ", e)
            datagramSocket.close()
            throw NotConnectableException(ConnectionReturn.INTERNAL_ERROR)
        }
    }

    override val name: String
        get() = "UDP/" + super.name
}