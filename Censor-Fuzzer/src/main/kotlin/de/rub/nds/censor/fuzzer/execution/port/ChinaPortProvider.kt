package de.rub.nds.censor.fuzzer.execution.port

import de.rub.nds.censor.fuzzer.constants.CensorshipValues.CHINA_PORT_RANGE_END
import de.rub.nds.censor.fuzzer.constants.CensorshipValues.CHINA_PORT_RANGE_START
import de.rub.nds.censor.fuzzer.constants.CensorshipValues.CHINA_RESIDUAL_CENSORSHIP_TIME
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import org.apache.logging.log4j.kotlin.Logging

class ChinaPortProvider(
        private val portRangeStart: Int = CHINA_PORT_RANGE_START,
        private val portRangeEnd: Int = CHINA_PORT_RANGE_END
) {

    private val channel: Channel<Int> = Channel(portRangeEnd-portRangeStart+1)

    /**
     * Must be called from async
     */
    suspend fun initialize() {
        for (port in portRangeStart..portRangeEnd) channel.send(port)
    }

    /**
     * Blocking operation.
     */
    suspend fun getPort(): Int {
         return channel.receive()
    }

    /**
     * Immediately releases a port without residual censorship being present.
     */
    suspend fun releaseUncensoredPort(port: Int) {
        if (port !in (portRangeStart..portRangeEnd)) {
            logger.warn("Returning port $port outside of port range ($portRangeStart,$portRangeEnd)")
        } else {
            channel.send(port)
        }
    }

    /**
     * Releases a port after waiting for the residual censorship to end.
     */
    suspend fun releaseCensoredPort(port: Int) {
        delay(CHINA_RESIDUAL_CENSORSHIP_TIME)
        releaseUncensoredPort(port)
    }

    companion object : Logging
}