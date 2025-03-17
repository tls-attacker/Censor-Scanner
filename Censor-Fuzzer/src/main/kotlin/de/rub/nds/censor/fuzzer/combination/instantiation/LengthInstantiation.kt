package de.rub.nds.censor.fuzzer.combination.instantiation

enum class LengthInstantiation : Instantiation {
    CORRECT,
    HALF,
    DOUBLE,
    ZERO,
    MAX,
    DEFAULT,
    ONLY_FIRST_SNI,
    GARBAGE_BYTES
}