package de.rub.nds.censor.core.constants

object ManipulationConstants {
    // maximum value contained in a 2 byte field such as SNI_NAME_LENGTH
    const val MAXIMUM_2_BYTE_FIELD_VALUE = 65535 // 2.0.pow(16.0) - 1
    const val GARBAGE_BYTE: Byte = 0x41

    // - TLS
    const val MESSAGE_LENGTH_FIELD_LENGTH = 2
    const val MESSAGE_VERSION_FIELD_LENGTH = 2
    const val MESSAGE_CONTENT_TYPE_FIELD_LENGTH = 1
    const val TLS_EXTENSIONS_LENGTH_LENGTH = 2
    const val TLS_EXTENSION_LENGTH_LENGTH = 2
    const val TLS_EXTENSION_TYPE_LENGTH = 2
    const val TLS_MAX_RECORD_SIZE_CORRECT = 16384 // 2.0.pow(14.0)
    const val TLS_MAX_RECORD_SIZE_POSSIBLE = MAXIMUM_2_BYTE_FIELD_VALUE
    const val RECORD_LENGTH_SIZE = 2
    const val MESSAGE_LENGTH_SIZE = 3
    const val HANDSHAKE_TYPE_SIZE = 1

    // - SNI
    const val SNI_NAME_LENGTH_LENGTH = 2
    const val SNI_NAME_TYPE_LENGTH = 1
    const val SNI_LIST_LENGTH_LENGTH = 2

    // - useful in manipulations, combine constants

    // header bytes in SNI list entry before hostname
    const val SNI_FIRST_HOSTNAME_TO_LIST_LENGTH = SNI_NAME_TYPE_LENGTH + SNI_NAME_LENGTH_LENGTH

    // bytes between extension length and first hostname in SNI
    const val SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH = SNI_NAME_TYPE_LENGTH + SNI_NAME_LENGTH_LENGTH + SNI_LIST_LENGTH_LENGTH

    // extension header
    const val TLS_EXTENSION_HEADER = TLS_EXTENSION_LENGTH_LENGTH + TLS_EXTENSION_TYPE_LENGTH

    const val MESSAGE_OFFSET_FOR_TOTAL_SIZE = MESSAGE_LENGTH_FIELD_LENGTH + MESSAGE_VERSION_FIELD_LENGTH + MESSAGE_CONTENT_TYPE_FIELD_LENGTH

    const val MESSAGE_LENGTH_TO_OUTER = MESSAGE_LENGTH_SIZE + HANDSHAKE_TYPE_SIZE

    const val STRIPPED_EXTENSION_LENGTH = 5

    // TODO: refine
    const val MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN = 707
}