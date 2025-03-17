package de.rub.nds.censor.core.util

import de.rub.nds.censor.core.connection.BasicTlsConnection
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage
import de.rub.nds.tlsattacker.core.workflow.action.SendAction

/**
 * Calculates certain
 */
class LengthCalculator(connection: BasicTlsConnection) {

    val messageLength: Int
    val extensionsLength: Int
    val sniExtensionLength: Int
    val sniListLength: Int
    val ecPointFormatsExtensionLength: Int
    val supportedGroupsExtensionLength: Int
    val signatureAlgorithmExtensionLength: Int
    val cipherSuitesLength: Int
    val extensionsCount: Int

    init {
        connection.initializeConnectionParameters()
        val message = (connection.state.workflowTrace.firstMessageAction as SendAction).configuredMessages[0] as CoreClientHelloMessage
        message.also {
            val preparator = message.getPreparator(connection.state.context)
            preparator.prepare()
        }
        messageLength = message.getLength().value
        extensionsLength = message.getExtensionsLength().value
        sniExtensionLength = message.getExtension(ServerNameIndicationExtensionMessage::class.java).extensionLength.value
        sniListLength = message.getExtension(ServerNameIndicationExtensionMessage::class.java).serverNameListLength.value
        ecPointFormatsExtensionLength = message.getExtension(ECPointFormatExtensionMessage::class.java).extensionLength.value
        supportedGroupsExtensionLength = message.getExtension(EllipticCurvesExtensionMessage::class.java).extensionLength.value
        signatureAlgorithmExtensionLength = message.getExtension(SignatureAndHashAlgorithmsExtensionMessage::class.java).extensionLength.value
        cipherSuitesLength = message.getCipherSuiteLength().value
        extensionsCount = message.getExtensions().size
    }
}