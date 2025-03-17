package de.rub.nds.censor.fuzzer.combination.instantiation

/**
 * Which combination of SNI/ESNI/ECH extensions to add
 */
enum class ExtensionInstantiation : Instantiation {
    NONE,
    SNI,
    ESNI,
    ECH7,
    ECH13,
    SNI_ESNI,
    SNI_ECH7,
    SNI_ECH13,
    ESNI_ECH7,
    ESNI_ECH13,
    SNI_ESNI_ECH7,
    SNI_ESNI_ECH13
}