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

import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.util.PcapCapturer
import org.apache.logging.log4j.kotlin.Logging
import java.util.*

/** Holds functions to connect to a server. Implements callable to be executed in the background.  */
abstract class Connection<Manipulation>(
    // Defines the timeframe in which this connection should be retried. Useful for residual
    // censorship analysis.
    // Internally, sockets still use a separate socketTimeout specifiable in the CensorScannerConfig
    var timeout: Int,
    val pcapCapturer: PcapCapturer? = null,
) {

    var manipulations: MutableList<Manipulation> = LinkedList()

    abstract val name: String

    /**
     * Executes the connection and throws a [NotConnectableException] if any exceptions occur during the connection.
     */
    @Throws(NotConnectableException::class)
    abstract suspend fun connect()

    fun registerManipulations(vararg manipulations: Manipulation) {
        this.manipulations.addAll(manipulations.filterNotNull())
    }

    fun registerManipulations(manipulationsList: List<Manipulation>?) {
        manipulationsList?.let { this.manipulations.addAll(manipulationsList) }
    }

    companion object : Logging
}