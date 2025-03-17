package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.PadHostnameToMaximumManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.PadToMaximumInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Pads the hostname at the given index to the maximum size
 */
@Serializable
class PadToMaximumStrategy(override val index: Int) : EntryStrategy<PadToMaximumInstantiation>() {
    override val defaultInstantiation: PadToMaximumInstantiation
        get() = PadToMaximumInstantiation.DEFAULT

    override val entryName: String
        get() = "PadToMaximum"

    override val strategyEnum: Strategies
        get() = Strategies.PAD_TO_MAXIMUM

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            PadToMaximumInstantiation.DEFAULT -> return listOf()
            PadToMaximumInstantiation.PAD_TO_MAXIMUM -> listOf(PadHostnameToMaximumManipulation(index))
        }
    }

    override fun getAllInstantiations(): List<PadToMaximumInstantiation> {
        return PadToMaximumInstantiation.entries
    }
}