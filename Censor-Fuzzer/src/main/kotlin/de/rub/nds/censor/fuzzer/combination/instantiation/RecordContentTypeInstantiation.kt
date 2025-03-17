package de.rub.nds.censor.fuzzer.combination.instantiation

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType

enum class RecordContentTypeInstantiation(val messageType: ProtocolMessageType) : Instantiation {
    UNKNOWN(ProtocolMessageType.UNKNOWN),
    CHANGE_CIPHER_SPEC(ProtocolMessageType.CHANGE_CIPHER_SPEC),
    ALERT(ProtocolMessageType.ALERT),
    HANDSHAKE(ProtocolMessageType.HANDSHAKE),
    APPLICATION_DATA(ProtocolMessageType.APPLICATION_DATA),
    HEARTBEAT(ProtocolMessageType.HEARTBEAT),
    TLS12_CID(ProtocolMessageType.TLS12_CID);
}