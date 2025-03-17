package de.rub.nds.censor.fuzzer.combination.instantiation

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType

enum class MessageTypeInstantiation(val messageType: HandshakeMessageType): Instantiation {
    UNKNOWN(HandshakeMessageType.UNKNOWN),
    HELLO_REQUEST(HandshakeMessageType.HELLO_REQUEST),
    CLIENT_HELLO(HandshakeMessageType.CLIENT_HELLO),
    SERVER_HELLO(HandshakeMessageType.SERVER_HELLO),
    CERTIFICATE(HandshakeMessageType.CERTIFICATE),
    SERVER_KEY_EXCHANGE(HandshakeMessageType.SERVER_KEY_EXCHANGE),
    CERTIFICATE_REQUEST(HandshakeMessageType.CERTIFICATE_REQUEST),
    SERVER_HELLO_DONE(HandshakeMessageType.SERVER_HELLO_DONE),
    CERTIFICATE_VERIFY(HandshakeMessageType.CERTIFICATE_VERIFY),
    CLIENT_KEY_EXCHANGE(HandshakeMessageType.CLIENT_KEY_EXCHANGE),
    FINISHED(HandshakeMessageType.FINISHED)
}