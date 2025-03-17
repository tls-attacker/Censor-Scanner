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
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetAddress
import java.net.UnknownHostException

/** Send an ICMP Ping to the server  */
class Ping(ip: IpAddress, timeout: Int, pcapCapturer: PcapCapturer? = null) :
    IpBoundConnection<Manipulation>(ip, timeout, pcapCapturer) {
    override val name: String
        get() = ip.address

    /**
     * Performs a ping to the server.
     *
     * @return TestResults Whether the server is reachable
     */
    @Throws(NotConnectableException::class)
    override suspend fun connect() {
        try {
            val inetAddress = withContext(Dispatchers.IO) {
                InetAddress.getByName(ip.address)
            }
            val reachable = withContext(Dispatchers.IO) {
                inetAddress.isReachable(timeout)
            }
            logger.debug("Connection $name is reachable: $reachable")
            if (!reachable) {
                throw NotConnectableException(ConnectionReturn.ICMP_UNREACHABLE)
            }
        } catch (e: UnknownHostException) {
            logger.warn("Ip address or hostname could not be parsed: ", e)
            throw NotConnectableException(ConnectionReturn.INTERNAL_ERROR)
        } catch (e: IOException) {
            logger.warn("Could reach address: ", e)
            throw NotConnectableException(ConnectionReturn.TIMEOUT)
        }
    }
}