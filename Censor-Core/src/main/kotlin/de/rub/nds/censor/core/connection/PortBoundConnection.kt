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

import de.rub.nds.censor.core.constants.Ip
import de.rub.nds.censor.core.constants.Port.Companion.isValid
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.network.ConnectionTuple
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import java.security.InvalidParameterException

abstract class PortBoundConnection<Manipulation>(
    ip: IpAddress,
    val serverPort: Int,
    timeout: Int,
    var clientPort: Int = -1,
    pcapCapturer: PcapCapturer? = null
) :
    IpBoundConnection<Manipulation>(ip, timeout, pcapCapturer) {

    protected var connectionTuple: ConnectionTuple? = null

    override val name: String
        get() = if (!isValid(clientPort)) {
            Ip.LOCALHOST.ipAddress.address + "->" + ip.address + ":" + serverPort
        } else {
            ("${Ip.LOCALHOST.ipAddress.address}:$clientPort->${ip.address}:$serverPort")
        }

    init {
        if (!isValid(serverPort)) {
            throw InvalidParameterException(
                "The given server port $serverPort is invalid. Must be between 0 and 65535"
            )
        }
        if (!isValid(clientPort) && clientPort != -1) {
            throw InvalidParameterException(
                "The given client port $clientPort is invalid. Must be between 0 and 65535"
            )
        }
    }

    abstract fun analyzeCancelledConnection(
        connectionTuple: ConnectionTuple?,
        exception: NotConnectableException,
        enableLog: Boolean,
        pcapCapturer: PcapCapturer?
    ): NotConnectableException
}