package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_OFFSET_FOR_TOTAL_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSION_HEADER
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_MAX_RECORD_SIZE_CORRECT
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_MAX_RECORD_SIZE_POSSIBLE
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage
import org.junit.jupiter.api.Assertions

class PaddingExtensionManipulationTest: SniTest<PaddingExtensionManipulation>() {
    override fun targetManipulations(): Collection<PaddingExtensionManipulation> {
        return listOf(
            PaddingExtensionManipulation(TLS_MAX_RECORD_SIZE_CORRECT),
            PaddingExtensionManipulation(TLS_MAX_RECORD_SIZE_POSSIBLE)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: PaddingExtensionManipulation, exception: Exception?) {
        val message = connection.state.workflowTrace.lastReceivingAction.receivedMessages[0]
        if (message !is CoreClientHelloMessage) throw Exception()

        val paddingExt = message.getExtension(PaddingExtensionMessage::class.java)
        assert(paddingExt != null) // padding extension was added

        // we subtract MESSAGE_OFFSET_FOR_TOTAL_SIZE here because we do not want the total message to exceed the size
        Assertions.assertEquals(manipulation.padToSize - MESSAGE_OFFSET_FOR_TOTAL_SIZE, message.getLength().value) // padding was successful
        Assertions.assertEquals(manipulation.padToSize - MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN  - MESSAGE_OFFSET_FOR_TOTAL_SIZE, message.getExtensionsLength().value) // Extensions length correct
        Assertions.assertEquals(manipulation.padToSize - MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN - defaultExtensionsLength -
                MESSAGE_OFFSET_FOR_TOTAL_SIZE - TLS_EXTENSION_HEADER, paddingExt.extensionLength.value) // padding extension correctly set
    }
}