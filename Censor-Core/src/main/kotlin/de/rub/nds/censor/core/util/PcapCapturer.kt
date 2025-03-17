/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.util

import de.rub.nds.censor.core.exception.PcapException
import de.rub.nds.censor.core.network.ConnectionTuple
import org.apache.logging.log4j.kotlin.Logging
import org.pcap4j.core.*
import org.pcap4j.core.BpfProgram.BpfCompileMode
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.Packet
import org.pcap4j.packet.TcpPacket
import org.pcap4j.packet.UdpPacket
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Capturer that records [PCAP files](https://en.wikipedia.org/wiki/Pcap) while a code
 * block is running.
 * @param interfaceName name of the network interface to capture on
 * @param bpfExpression optional filter expression for the Berkeley Packet Filter (BPF)
 * @param snapshotLengthBytes maximum length of a captured packet.
 */

class PcapCapturer(
    interfaceName: String = "any",
    promiscuousMode: PromiscuousMode = PromiscuousMode.NONPROMISCUOUS,
    bpfExpression: String = "",
    snapshotLengthBytes: Int = 65535,
    readTimeoutMilliseconds: Int = 1000
) : AutoCloseable, Runnable, PacketListener {

    /** PCAP handle that reads from the network interface.  */
    private val pcapHandle: PcapHandle

    /** The thread which takes care of the actual capturing.  */
    private val captureThread: Thread

    /** The thread-safe data structure that contains the TCP queues for an identification. */
    private val captureQueuesTcp: MutableMap<ConnectionTuple, ConcurrentLinkedQueue<TcpPacket>>

    /** The thread-safe data structure that contains the UDP queues for an identification. */
    private val captureQueuesUdp: MutableMap<ConnectionTuple, ConcurrentLinkedQueue<UdpPacket>>

    /**
     * Create a new Capturer object and start capturing immediately, until [.close] is called.
     */
    init {
        captureQueuesTcp =
            ConcurrentHashMap<ConnectionTuple, ConcurrentLinkedQueue<TcpPacket>>() // init ConcurrentHashMap
        captureQueuesUdp = ConcurrentHashMap<ConnectionTuple, ConcurrentLinkedQueue<UdpPacket>>()
        val device = if (interfaceName == "local") {
            Pcaps.findAllDevs().first { it.isLoopBack && it.isRunning }
        } else {
            Pcaps.getDevByName(interfaceName)
        }
        if (device == null) {
            throw IllegalArgumentException(
                "Device was not found! If you are not using Linux, either select 'local' interfacename for loopback device or " +
                        "choose the device that you want to capture on explicitly!"
            )
        }
        pcapHandle = device.openLive(snapshotLengthBytes, promiscuousMode, readTimeoutMilliseconds)
        if (bpfExpression.isNotEmpty()) {
            pcapHandle.setFilter(bpfExpression, BpfCompileMode.OPTIMIZE)
        }
        captureThread = Thread(this, "pcap-capture")
    }

    fun start() {
        captureThread.start()
    }

    fun stop() {
        pcapHandle.breakLoop()
    }

    /**
     * Creates a queue for the given [ConnectionTuple].
     */
    @Throws(PcapException::class)
    fun register(connectionTuple: ConnectionTuple) {
        if (connectionTuple.tcp) {
            synchronized(captureQueuesTcp) {
                if (captureQueuesTcp.containsKey(connectionTuple)) {
                    throw PcapException("Queue already registered for $connectionTuple.")
                }
                captureQueuesTcp[connectionTuple] = ConcurrentLinkedQueue<TcpPacket>()
            }
        } else {
            synchronized(captureQueuesUdp) {
                if (captureQueuesUdp.containsKey(connectionTuple)) {
                    throw PcapException("Queue already registered for $connectionTuple.")
                }
                captureQueuesUdp[connectionTuple] = ConcurrentLinkedQueue<UdpPacket>()
            }
        }
    }

    /**
     * Removes the queue of the given [ConnectionTuple].
     */
    fun deregister(connectionTuple: ConnectionTuple) {
        // if null do nothing
        if (connectionTuple.tcp) {
            captureQueuesTcp.remove(connectionTuple)
        } else {
            captureQueuesUdp.remove(connectionTuple)
        }
    }

    fun getTcpQueue(connectionTuple: ConnectionTuple): ConcurrentLinkedQueue<TcpPacket>? {
        return captureQueuesTcp[connectionTuple]
    }

    fun getUdpQueue(connectionTuple: ConnectionTuple): ConcurrentLinkedQueue<UdpPacket>? {
        return captureQueuesUdp[connectionTuple]
    }

    override fun gotPacket(packet: Packet) {
        try {
            // only analyze TCP packets or UDP packets
            if (packet.contains(IpV4Packet::class.java)) {
                val ipv4Packet = packet.get(IpV4Packet::class.java)
                if (packet.contains(TcpPacket::class.java)) {
                    val tcpPacket = packet.get(TcpPacket::class.java)
                    val connectionTuple = ConnectionTuple(
                        ipv4Packet.header.srcAddr.toString().removePrefix("/"),
                        tcpPacket.header.srcPort.valueAsInt(),
                        ipv4Packet.header.dstAddr.toString().removePrefix("/"),
                        tcpPacket.header.dstPort.valueAsInt(),
                        true
                    )
                    captureQueuesTcp[connectionTuple]?.add(tcpPacket)
                } else if (packet.contains(UdpPacket::class.java)) {
                    val udpPacket = packet.get(UdpPacket::class.java)
                    val connectionTuple = ConnectionTuple(
                        ipv4Packet.header.srcAddr.toString().removePrefix("/"),
                        udpPacket.header.srcPort.valueAsInt(),
                        ipv4Packet.header.dstAddr.toString().removePrefix("/"),
                        udpPacket.header.dstPort.valueAsInt(),
                        false
                    )
                    captureQueuesUdp[connectionTuple]?.add(udpPacket)
                }
            }
        } catch (err: NotOpenException) { //TODO: Handle correct exceptions here for not working packet types
            throw PcapException("Failed to dump captured PCAP packet (file not open)", err)
        }
    }

    override fun run() {
        // First, loop over available packets. This will wait for more packets
        // if none are available, unless `breakLoop()` has been called.
        try {
            pcapHandle.loop(-1, this)
        } catch (err: PcapNativeException) {
            throw PcapException("Failed to capture PCAP packets", err)
        } catch (err: NotOpenException) {
            throw PcapException("Failed to capture PCAP packets", err)
        } catch (err: InterruptedException) {
            // `breakLoop()` has been called, stop capturing.
        }

        // It's possible that more packets have been queued but not been
        // processed yet. Hence, we call `pcap_dispatch` here, which is similar
        // to `pcap_loop` but does not wait for more packets once the read
        // timeout has been reached.
        //
        // Additionally, we enable non-blocking mode to avoid waiting for
        // packet that haven't been queued altogether.
        try {
            pcapHandle.blockingMode = PcapHandle.BlockingMode.NONBLOCKING
        } catch (err: PcapNativeException) {
            throw PcapException("Failed to set PCAP handle into non-blocking mode", err)
        } catch (err: NotOpenException) {
            throw PcapException("Failed to set PCAP handle into non-blocking mode", err)
        }
        try {
            pcapHandle.dispatch(-1, this)
        } catch (err: PcapNativeException) {
            throw PcapException("Failed to capture queued PCAP packets", err)
        } catch (err: NotOpenException) {
            throw PcapException("Failed to capture queued PCAP packets", err)
        } catch (err: InterruptedException) {
            throw PcapException("Failed to capture queued PCAP packets", err)
        }

        pcapHandle.close()
    }

    @Throws(PcapNativeException::class)
    override fun close() {
        // Break the `pcap_loop` call in the capture thread.
        try {
            pcapHandle.breakLoop()
        } catch (err: NotOpenException) {
            throw PcapException("Failed to break PCAP capture loop (handle not open)", err)
        }

        // Now wait until the capture thread exits.
        try {
            captureThread.join()
        } catch (err: InterruptedException) {
            throw PcapException(
                "PCAP capture thread was interrupted while trying to join it", err
            )
        }
    }

    companion object : Logging
}