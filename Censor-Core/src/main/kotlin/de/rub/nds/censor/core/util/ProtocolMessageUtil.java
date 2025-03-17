package de.rub.nds.censor.core.util;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessageHandler;

/** Code that relies on unsafe Java calls goes here. */
public class ProtocolMessageUtil {

    public static void updateDigestForProtocolMessage(ProtocolMessage message, TlsContext context) {
        ProtocolMessageHandler handler = message.getHandler(context.getContext());
        handler.updateDigest(message, true);
    }

    public static void adjustContextForProtocolMessage(
            ProtocolMessage message, TlsContext context) {
        ProtocolMessageHandler handler = message.getHandler(context.getContext());
        handler.adjustContext(message);
    }

    public static void adjustContextAfterSerializeForProtocolMessage(
            ProtocolMessage message, TlsContext context) {
        ProtocolMessageHandler handler = message.getHandler(context.getContext());
        handler.adjustContextAfterSerialize(message);
    }
}
