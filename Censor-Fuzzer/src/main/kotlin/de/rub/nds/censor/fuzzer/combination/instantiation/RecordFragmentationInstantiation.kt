package de.rub.nds.censor.fuzzer.combination.instantiation

enum class RecordFragmentationInstantiation : Instantiation {
    NONE,

    IN_MESSAGE_HEADER_NONE,

    BEFORE_SNI_NONE,
    IN_HOSTNAME_NONE,
    AFTER_SNI_NONE,

    BEFORE_SNI_INVALID,
    IN_HOSTNAME_INVALID,
    AFTER_SNI_INVALID,

    BEFORE_SNI_CCS_VALID,
    IN_HOSTNAME_CCS_VALID,
    AFTER_SNI_CCS_VALID,

    BEFORE_SNI_CCS_INVALID,
    IN_HOSTNAME_CCS_INVALID,
    AFTER_SNI_CCS_INVALID,

    BEFORE_SNI_ALERT_INCOMPLETE,
    IN_HOSTNAME_ALERT_INCOMPLETE,
    AFTER_SNI_ALERT_INCOMPLETE,

    BEFORE_SNI_ALERT_INTERNAL_WARN,
    IN_HOSTNAME_ALERT_INTERNAL_WARN,
    AFTER_SNI_ALERT_INTERNAL_WARN,

    BEFORE_SNI_ALERT_INTERNAL_FATAL,
    IN_HOSTNAME_ALERT_INTERNAL_FATAL,
    AFTER_SNI_ALERT_INTERNAL_FATAL,

    BEFORE_SNI_HANDSHAKE_NULL_BYTE,
    IN_HOSTNAME_HANDSHAKE_NULL_BYTE,
    AFTER_SNI_HANDSHAKE_NULL_BYTE,

    BEFORE_SNI_APPLICATION_DATA_NULL_BYTE,
    IN_HOSTNAME_APPLICATION_DATA_NULL_BYTE,
    AFTER_SNI_APPLICATION_DATA_NULL_BYTE,

    BEFORE_SNI_HEARTBEAT_REQUEST,
    IN_HOSTNAME_HEARTBEAT_REQUEST,
    AFTER_SNI_HEARTBEAT_REQUEST,

    BEFORE_SNI_HEARTBEAT_RESPONSE,
    IN_HOSTNAME_HEARTBEAT_RESPONSE,
    AFTER_SNI_HEARTBEAT_RESPONSE,

    BEFORE_SNI_HEARTBEAT_INCOMPLETE,
    IN_HOSTNAME_HEARTBEAT_INCOMPLETE,
    AFTER_SNI_HEARTBEAT_INCOMPLETE
}