package de.rub.nds.censor.core.constants

/**
 * All GREASE types as specified in https://datatracker.ietf.org/doc/rfc8701/
 */
enum class GreaseType(val extensionBytes: ByteArray) {
    GREASE_00(byteArrayOf(0x0A.toByte(), 0x0A.toByte())),
    GREASE_01(byteArrayOf(0x1A.toByte(), 0x1A.toByte())),
    GREASE_02(byteArrayOf(0x2A.toByte(), 0x2A.toByte())),
    GREASE_03(byteArrayOf(0x3A.toByte(), 0x3A.toByte())),
    GREASE_04(byteArrayOf(0x4A.toByte(), 0x4A.toByte())),
    GREASE_05(byteArrayOf(0x5A.toByte(), 0x5A.toByte())),
    GREASE_06(byteArrayOf(0x6A.toByte(), 0x6A.toByte())),
    GREASE_07(byteArrayOf(0x7A.toByte(), 0x7A.toByte())),
    GREASE_08(byteArrayOf(0x8A.toByte(), 0x8A.toByte())),
    GREASE_09(byteArrayOf(0x9A.toByte(), 0x9A.toByte())),
    GREASE_10(byteArrayOf(0xAA.toByte(), 0xAA.toByte())),
    GREASE_11(byteArrayOf(0xBA.toByte(), 0xBA.toByte())),
    GREASE_12(byteArrayOf(0xCA.toByte(), 0xCA.toByte())),
    GREASE_13(byteArrayOf(0xDA.toByte(), 0xDA.toByte())),
    GREASE_14(byteArrayOf(0xEA.toByte(), 0xEA.toByte())),
    GREASE_15(byteArrayOf(0xFA.toByte(), 0xFA.toByte()));

}