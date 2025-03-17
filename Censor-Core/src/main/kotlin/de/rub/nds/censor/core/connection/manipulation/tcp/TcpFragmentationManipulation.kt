/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tcp

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.tlsattacker.core.connection.OutboundConnection
import de.rub.nds.tlsattacker.core.state.State
import de.rub.nds.tlsattacker.transport.TransportHandlerType
import de.rub.nds.tlsattacker.transport.tcp.fragmentation.ClientTcpFragmentationTransportHandler
import java.util.*

/**
 * Enables TcpFragmentation on a Tcp Socket. Only applicable to [TlsConnection] because Javas
 * TCP sockets do not support such a feature. TODO: write test
 */
class TcpFragmentationManipulation(private val segmentSize: Int) : TlsManipulation() {
    override fun afterConnectionPrepare(outboundConnection: OutboundConnection?) {
        outboundConnection!!.transportHandlerType = TransportHandlerType.TCP_FRAGMENTATION
    }

    override fun afterTransportHandlerInit(state: State) {
        (state.tlsContext.transportHandler as ClientTcpFragmentationTransportHandler).packetChunks = segmentSize
    }

    override val name: String
        get() = "tcp_fragmentation"
}