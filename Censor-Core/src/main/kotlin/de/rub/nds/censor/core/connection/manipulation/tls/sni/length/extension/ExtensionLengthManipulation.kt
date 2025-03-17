package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.extension

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.core.util.IntegerMultiplyWithMaximumModification
import de.rub.nds.censor.core.util.Util.getSniExtension
import de.rub.nds.modifiablevariable.ModifiableVariableFactory
import de.rub.nds.tlsattacker.core.state.State

/**
 * Modifies the length bytes of the SNI extension.
 */
class ExtensionLengthManipulation(val extensionLengthModifier: Double) : TlsManipulation() {
    override val name: String
        get() = "sni_ext_length(listLengthModifier=$extensionLengthModifier)"

    override fun afterStateGeneration(state: State) {
        val incorrectExtensionLengthModification = IntegerMultiplyWithMaximumModification(
            extensionLengthModifier,
            MAXIMUM_2_BYTE_FIELD_VALUE
        ) // create modification and add afterward
        val serverNameIndication = state.workflowTrace.getSniExtension()
        serverNameIndication.extensionLength = ModifiableVariableFactory.createIntegerModifiableVariable()
        serverNameIndication.extensionLength.modification = incorrectExtensionLengthModification
    }
}