package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.AsciiParityBitManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.DecoderConfusionInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Flips the ascii parity bit of the hostname at given index
 */
@Serializable
class DecoderConfusionStrategy(override val index: Int) : EntryStrategy<DecoderConfusionInstantiation>() {
    override val defaultInstantiation: DecoderConfusionInstantiation
        get() = DecoderConfusionInstantiation.DEFAULT

    override val entryName: String
        get() = "AsciiParityFlip"

    override val strategyEnum: Strategies
        get() = Strategies.ASCII_PARITY_FLIP

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            DecoderConfusionInstantiation.DEFAULT -> return listOf()
            DecoderConfusionInstantiation.SET_ALL_HIGHEST_BITS -> listOf(AsciiParityBitManipulation(index))
        }
    }

    override fun getAllInstantiations(): List<DecoderConfusionInstantiation> {
        return DecoderConfusionInstantiation.entries
    }
}