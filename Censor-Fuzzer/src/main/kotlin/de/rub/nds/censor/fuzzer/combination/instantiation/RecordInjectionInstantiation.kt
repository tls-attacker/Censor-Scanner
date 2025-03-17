package de.rub.nds.censor.fuzzer.combination.instantiation

/**
 * Instantiations for possible record injections. Default is no injection. Only for injecting records before / after CH message.
 * Record injection for records in between record fragmentation is included as instantiations of record fragmentation directly.
 */
enum class RecordInjectionInstantiation : Instantiation {
    NONE,
    BEFORE_INVALID_TYPE,
    BEFORE_CCS_VALID,
    BEFORE_CCS_INVALID,
    BEFORE_ALERT_INCOMPLETE,
    BEFORE_ALERT_INTERNAL_WARN,
    BEFORE_ALERT_INTERNAL_FATAL,
    BEFORE_HANDSHAKE_NULL_BYTE,
    BEFORE_APPLICATION_DATA_NULL_BYTE,
    BEFORE_HEARTBEAT_REQUEST,
    BEFORE_HEARTBEAT_RESPONSE,
    BEFORE_HEARTBEAT_INCOMPLETE,
    AFTER_INVALID_TYPE,
    AFTER_CCS_VALID,
    AFTER_CCS_INVALID,
    AFTER_ALERT_INCOMPLETE,
    AFTER_ALERT_INTERNAL_WARN,
    AFTER_ALERT_INTERNAL_FATAL,
    AFTER_HANDSHAKE_NULL_BYTE,
    AFTER_APPLICATION_DATA_NULL_BYTE,
    AFTER_HEARTBEAT_REQUEST,
    AFTER_HEARTBEAT_RESPONSE,
    AFTER_HEARTBEAT_INCOMPLETE
}