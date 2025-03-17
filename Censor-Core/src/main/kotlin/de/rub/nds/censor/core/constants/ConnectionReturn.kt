package de.rub.nds.censor.core.constants

/**
 * Holds errors with which a connection can fail, reset might indicate censorship.
 */
enum class ConnectionReturn {

    // everything as expected
    WORKING,

    // cannot determine what happened, indicates missing implementation
    UNKNOWN,

    // not applicable combination
    INAPPLICABLE,

    // could not yet determine what happened, indicate further analysis should happen
    ANALYZE_FURTHER,

    // placeholder for uninitialized values, preferable to [null]
    UNSET,

    // for caught exception etc., should never be returned in correctly evaluated connections
    INTERNAL_ERROR,
    ALREADY_DEFAULT,

    // HTTP responses
    NO_HTTP,
    DIFFERENT_HTTP,

    // TLS responses
    TLS_ALERT,
    NO_CERTIFICATE,
    NO_CERTIFICATE_BUT_WORKING,
    WRONG_CERTIFICATE,
    WRONG_CERTIFICATE_BUT_WORKING,
    NO_SERVER_ANSWER,

    // TCP responses
    TIMEOUT,
    TCP_RESET,
    TCP_RESET_TWO,
    TCP_RESET_THREE,
    TCP_RESET_MANY,

    // HTTP
    BAD_REQUEST,

    // Ping response
    ICMP_UNREACHABLE,

    // ECHO
    UNREACHABLE,
    LESS_DATA,
    DIFFERENT_DATA,

    // DECISION
    UNDECIDED,
    CENSORED;

    fun working(): Boolean {
        return this == WORKING || this == WRONG_CERTIFICATE_BUT_WORKING || this == NO_CERTIFICATE_BUT_WORKING
    }

    fun indicatesSniCensorship(censor: Censor): Boolean {
        return when(censor) {
            Censor.RUSSIA -> this == NO_SERVER_ANSWER
            Censor.IRAN -> this == TCP_RESET || this == TCP_RESET_TWO || this == TCP_RESET_THREE || this == TCP_RESET_MANY
            Censor.CHINA -> this == TCP_RESET || this == TCP_RESET_TWO || this == TCP_RESET_THREE || this == TCP_RESET_MANY
        }
    }
}