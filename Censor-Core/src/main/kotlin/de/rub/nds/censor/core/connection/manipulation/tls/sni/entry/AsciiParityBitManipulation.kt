/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.tlsattacker.core.config.Config

/**
 * Flips the highest bit of every letter in the hostname to 1. Ascii is only defined on 7 bit
 * with the other bit possibly being used for parity. So we change letters where the parity can be
 * set to 1.
 */
class AsciiParityBitManipulation(private val entry: Int) : SniEntryManipulation(entry) {
    override val name: String
        get() = "ascii_parity_bit(entry=$entry)"

    override fun afterConfigInit(tlsConfig: Config) {
        val serverNamePair = getServerNamePair(tlsConfig)

        val hostname = serverNamePair.serverNameConfig
        serverNamePair.serverNameConfig =
            hostname.map { (it.toInt() or 128).toByte() }.toByteArray() // flip all parity bits
    }
}