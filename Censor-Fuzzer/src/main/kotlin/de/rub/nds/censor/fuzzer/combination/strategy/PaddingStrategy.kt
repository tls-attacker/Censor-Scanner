package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.AddCipherSuitesAsPaddingManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.PaddingExtensionManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.PaddingInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Strategy for adding padding
 */
@Serializable
class PaddingStrategy : Strategy<PaddingInstantiation>() {
    override val defaultInstantiation: PaddingInstantiation
        get() = PaddingInstantiation.NONE

    override val name: String
        get() = "Padding"

    override val strategyEnum: Strategies
        get() = Strategies.PADDING

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            PaddingInstantiation.NONE -> listOf()
            PaddingInstantiation.PADDING_EXT_MAX_RECORD -> listOf(PaddingExtensionManipulation(this.instantiation!!.padToSize))
            PaddingInstantiation.PADDING_EXT_MAX_MESSAGE -> listOf(PaddingExtensionManipulation(this.instantiation!!.padToSize))
            PaddingInstantiation.CIPHER_SUITES_MAX_RECORD -> listOf(AddCipherSuitesAsPaddingManipulation(this.instantiation!!.padToSize))
            PaddingInstantiation.CIPHER_SUITES_MAX_MESSAGE -> listOf(AddCipherSuitesAsPaddingManipulation(this.instantiation!!.padToSize))
        }
    }

    override fun getAllInstantiations(): List<PaddingInstantiation> {
        return PaddingInstantiation.entries
    }
}