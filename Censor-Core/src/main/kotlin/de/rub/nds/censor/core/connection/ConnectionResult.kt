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

import de.rub.nds.censor.core.constants.ConnectionReturn

class ConnectionResult(
    val error: ConnectionReturn, // type of connection error if any
    private val responseTime: Int, // time it took for the server to respond
    private val timeout: Int // original timeout of the connection
) {

    constructor(error: ConnectionReturn, timeout: Int) : this(error, -1, timeout)
    constructor(responseTime: Int, timeout: Int) : this(ConnectionReturn.WORKING, responseTime, timeout)

    val responseTimeMilliSeconds: Int
        get() = responseTime

    val responseTimeSeconds: Int
        get() = responseTime / 1000

    val timeoutMilliSeconds: Int
        get() = timeout

    val timeoutTimeSeconds: Int
        get() = timeout / 1000
}