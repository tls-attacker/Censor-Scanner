/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.exception

/**
 * Exception during pcap parsing or writing.
 */
class PcapException(
    override val message: String? = null,
    override val cause: Throwable? = null,
    enableSuppression: Boolean = false,
    writableStackTrace: Boolean = false
) : RuntimeException(message, cause, enableSuppression, writableStackTrace)