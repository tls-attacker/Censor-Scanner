package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.util.Util.getExtensions
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import de.rub.nds.tlsattacker.core.state.State

/**
 * Removes all Sni extensions from the connection.
 */
class RemoveSniExtensionsManipulation: TlsManipulation() {
    override val name: String
        get() = "remove_sni"

    override fun afterStateGeneration(state: State) {
        state.workflowTrace.getExtensions().removeAll { it is ServerNameIndicationExtensionMessage }
    }
}