package de.rub.nds.censor.core.connection.manipulation.tls.extension.length

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.core.util.IntegerMultiplyWithMaximumModification
import de.rub.nds.censor.core.util.Util.getClientHelloMessage
import de.rub.nds.modifiablevariable.ModifiableVariableFactory
import de.rub.nds.tlsattacker.core.state.State

/**
 * Modifies the length bytes of the extensions.
 */
class ExtensionsLengthManipulation(val extensionsLengthModifier: Double) : TlsManipulation() {
    override val name: String
        get() = "extensions_length(listLengthModifier=$extensionsLengthModifier)"

    override fun afterStateGeneration(state: State) {
        val incorrectExtensionLengthModification = IntegerMultiplyWithMaximumModification(
            extensionsLengthModifier,
            MAXIMUM_2_BYTE_FIELD_VALUE
        ) // create modification and add afterward

        val message = state.workflowTrace.getClientHelloMessage()
        message.extensionsLength = ModifiableVariableFactory.createIntegerModifiableVariable()
        message.extensionsLength.modification = incorrectExtensionLengthModification
    }
}