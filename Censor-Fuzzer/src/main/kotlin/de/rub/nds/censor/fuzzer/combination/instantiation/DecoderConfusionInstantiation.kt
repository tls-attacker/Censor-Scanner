package de.rub.nds.censor.fuzzer.combination.instantiation

enum class DecoderConfusionInstantiation : Instantiation {
    DEFAULT,
    // maybe highest bit is ignored by ascii parser
    SET_ALL_HIGHEST_BITS
}