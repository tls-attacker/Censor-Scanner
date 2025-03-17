package de.rub.nds.censor.fuzzer.combination.instantiation

/**
 * Bytes with which to override the extension type
 */
enum class ExtensionTypeInstantiation(val extensionBytes: ByteArray) : Instantiation {
    // DEFAULT has no bytes for overriding
    DEFAULT(byteArrayOf()),
    WRONG0x9999(byteArrayOf(0x99.toByte(), 0x99.toByte()))
}