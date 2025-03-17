/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2017-2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.network

import kotlinx.serialization.Serializable
import java.lang.IllegalArgumentException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Constructor
 *
 * @throws IllegalArgumentException If the ip address is not valid
 */
@Serializable
class Ipv4Address(override val address: String) : IpAddress() {

    /**
     * Constructor
     *
     * @throws IllegalArgumentException If the ip address is not valid
     */
    init {
        if (!isValid(address)) {
            throw IllegalArgumentException("IP4 address $address is invalid")
        }
    }

    override fun isValid(address: String): Boolean = Companion.isValid(address)

    override fun isLocalhost(): Boolean {
        return this.address.startsWith("127.")
    }

    companion object {
        fun isValid(address: String): Boolean = try {
            InetAddress.getAllByName(address).any { it is Inet4Address && it.hostAddress == address }
        } catch (ex: UnknownHostException) {
            false
        }
    }
}