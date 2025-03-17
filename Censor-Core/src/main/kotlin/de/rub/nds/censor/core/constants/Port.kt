/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2017-2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.constants

/** Enum over known ports  */
enum class Port(val portNumber: Int) {
    MIN(0),
    MAX(65535),
    HTTPS(443),
    QUIC(443),
    DTLS(4433),
    ECHO(7),
    DNS_OVER_TLS(853),
    DNS_OVER_QUIC(853),
    DNS_OVER_HTTPS(443),
    DNS(53);

    companion object {
        @JvmStatic
        fun isValid(port: Int): Boolean {
            return port in MIN.portNumber..MAX.portNumber
        }
    }
}