package de.rub.nds.censor.core.connection.manipulation.tls.message

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.util.Util.getExtensions
import de.rub.nds.censor.core.util.Util.getSniExtension
import de.rub.nds.tlsattacker.core.state.State

/**
 * Moves the SNI extension to the desired position in the extension list. Use negative numbers for reverse indexing.
 */
class MoveSniManipulation(val position: Int): TlsManipulation() {
    override val name: String
        get() = "move_sni(position=$position)"

    override fun afterStateGeneration(state: State) {

        val extensions = state.workflowTrace.getExtensions()
        val sniExtension = state.workflowTrace.getSniExtension()
        extensions.remove(sniExtension)
        val newPosition = if (position < 0) { // to last pos
            extensions.size + position + 1
        } else {
            position
        }
        extensions.add(newPosition, sniExtension)
    }
}