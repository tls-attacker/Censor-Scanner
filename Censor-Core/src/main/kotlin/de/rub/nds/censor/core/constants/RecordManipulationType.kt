package de.rub.nds.censor.core.constants

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType

/**
 * Different ProtocolMessageType mapping for record injection. Allows the setting of specific content during record creation.
 */
enum class RecordManipulationType(val protocolType: ProtocolMessageType) {
    INVALID_TYPE(ProtocolMessageType.UNKNOWN),
    CHANGE_CIPHER_SPEC_VALID(ProtocolMessageType.CHANGE_CIPHER_SPEC),
    CHANGE_CIPHER_SPEC_INVALID(ProtocolMessageType.CHANGE_CIPHER_SPEC),
    ALERT_INCOMPLETE(ProtocolMessageType.ALERT),
    ALERT_INTERNAL_WARN(ProtocolMessageType.ALERT),
    ALERT_INTERNAL_FATAL(ProtocolMessageType.ALERT),
    HANDSHAKE_NULL_BYTE(ProtocolMessageType.HANDSHAKE),
    APPLICATION_DATA_NULL_BYTE(ProtocolMessageType.APPLICATION_DATA),
    HEARTBEAT_REQUEST(ProtocolMessageType.HEARTBEAT),
    HEARTBEAT_RESPONSE(ProtocolMessageType.HEARTBEAT),
    HEARTBEAT_INCOMPLETE(ProtocolMessageType.HEARTBEAT)
}