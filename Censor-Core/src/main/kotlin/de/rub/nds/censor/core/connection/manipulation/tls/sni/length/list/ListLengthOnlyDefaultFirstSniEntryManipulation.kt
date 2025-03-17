package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_FIRST_HOSTNAME_TO_LIST_LENGTH
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage

class ListLengthOnlyDefaultFirstSniEntryManipulation(private val correctHostname: String) : TlsManipulation() {
    override val name: String
        get() = "sni_list_length(default)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only set extensions length to SNI-dependant value in ClientHello messages, skipping")
            return
        }

        val sni = message.getExtension(ServerNameIndicationExtensionMessage::class.java)
        val explicitModification = IntegerExplicitValueModification()
        explicitModification.explicitValue = correctHostname.length + SNI_FIRST_HOSTNAME_TO_LIST_LENGTH
        if (explicitModification.explicitValue == sni.serverNameListLength.value) {
            throw NotConnectableException(ConnectionReturn.ALREADY_DEFAULT, "List length is already ${explicitModification.explicitValue}")
        }
        sni.serverNameListLength.modification = explicitModification
    }
}