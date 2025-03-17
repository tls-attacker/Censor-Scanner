/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.constants

/**
 * Whether to execute a direct scan or an ECHO scan.
 */
enum class CensorScanType {
    DIRECT,
    ECHO,
    SIMPLE
}