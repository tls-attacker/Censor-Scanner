package de.rub.nds.censor.fuzzer.constants

/**
 * Enumerator of all subclasses of [Strategy<*>]. Needs a 1to1 mapping and is ordered.
 */
enum class Strategies : Comparable<Strategies> {
    // The order is important for sorting strategies

    // Non-SNI strategies
    EXTENSION,
    VERSION,

    // Record
    RECORD_FRAGMENTATION,
    RECORD_INJECTION,
    RECORD_VERSION,
    RECORD_LENGTH,
    RECORD_CONTENT_TYPE,

    // message
    MESSAGE_TYPE,
    MESSAGE_VERSION,
    MESSAGE_LENGTH,
    PADDING,

    // general extensions
    EXTENSIONS_LENGTH,

    // general SNI
    ADDITIONAL_SNI,
    MOVE_SNI,
    EXTENSION_TYPE,
    LIST_LENGTH,
    EXTENSION_LENGTH,

    // Additional entry strategy - Always place before SNI-entry strategies
    ADDITIONAL_ENTRIES,

    // SNI-entry strategies, that dont combine
    REPLACE_WITH_HARMLESS,

    // SNI-entry strategies that combine
    ADD_SUBDOMAIN,
    INJECT_SYMBOL,
    CHANGE_CASE,
    ASCII_PARITY_FLIP,
    NAME_LENGTH,
    NAME_TYPE,
    PAD_TO_MAXIMUM,
}