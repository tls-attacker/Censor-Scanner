package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.core.util.IntegerMultiplyWithMaximumModification
import de.rub.nds.censor.core.util.Util.getSniExtension
import de.rub.nds.modifiablevariable.ModifiableVariableFactory
import de.rub.nds.tlsattacker.core.state.State

/**
 * Modifies the length bytes of the list in the SNI extension.
 */
class ListLengthManipulation(val listLengthModifier: Double) : TlsManipulation() {

    override val name: String
        get() = "sni_list_length(listLengthModifier=$listLengthModifier)"

    override fun afterStateGeneration(state: State) {
        val incorrectListLengthModification = IntegerMultiplyWithMaximumModification(
            listLengthModifier,
            MAXIMUM_2_BYTE_FIELD_VALUE
        ) // create modification and add afterward
        val sni = state.workflowTrace.getSniExtension()
        sni.serverNameListLength = ModifiableVariableFactory.createIntegerModifiableVariable()
        sni.serverNameListLength.modification = incorrectListLengthModification
    }
}