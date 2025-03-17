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
 * All standardized versions of the ECH extension (state of https://datatracker.ietf.org/doc/draft-ietf-tls-esni/17/)
 */
enum class EncryptedClientHelloVersion( // draft 13-17 inclusive all share FF0D version bytes
    val versionBytes: ByteArray
) {
    DRAFT_ESNI(byteArrayOf(0xFF.toByte(), 0xCE.toByte())),

    // DRAFT _06 did not have a version number
    DRAFT_07(byteArrayOf(0xFF.toByte(), 0x02.toByte())),
    DRAFT_08(byteArrayOf(0xFE.toByte(), 0x08.toByte())),
    DRAFT_09(byteArrayOf(0xFE.toByte(), 0x09.toByte())),
    DRAFT_10(byteArrayOf(0xFE.toByte(), 0x0a.toByte())),
    DRAFT_11(byteArrayOf(0xFE.toByte(), 0x0b.toByte())),
    DRAFT_12(byteArrayOf(0xFE.toByte(), 0x0c.toByte())),
    DRAFT_13_14_15_16_17(byteArrayOf(0xFE.toByte(), 0x0D.toByte()));

    companion object {
        @JvmStatic
        val firstAndLast: List<EncryptedClientHelloVersion>
            get() = listOf(DRAFT_07, DRAFT_13_14_15_16_17)
    }
}