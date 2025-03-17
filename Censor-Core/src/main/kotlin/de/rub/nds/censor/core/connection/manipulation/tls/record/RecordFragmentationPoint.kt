package de.rub.nds.censor.core.connection.manipulation.tls.record

enum class RecordFragmentationPoint {
    BEFORE_SNI,
    IN_HOSTNAME,
    AFTER_SNI,
    IN_MESSAGE_HEADER
}