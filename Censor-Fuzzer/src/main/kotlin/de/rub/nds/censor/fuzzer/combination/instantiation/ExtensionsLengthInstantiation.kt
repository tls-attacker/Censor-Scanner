package de.rub.nds.censor.fuzzer.combination.instantiation

enum class ExtensionsLengthInstantiation : Instantiation {
    CORRECT,
    HALF,
    DOUBLE,
    ZERO,
    MAX,
    DEFAULT,
    ONLY_FIRST_SNI,
    STRIP_LAST_EXT,
    GARBAGE_BYTES
}