package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.fuzzer.combination.instantiation.Instantiation
import kotlinx.serialization.Serializable

/**
 * Abstract superclass for all strategies that operate on a single SNI entry
 */
@Serializable
sealed class EntryStrategy<Parametrization : Instantiation> : Strategy<Parametrization>() {

    abstract val index: Int

    override val name: String
        get() = "$entryName(sniEntry: $index)"

    abstract val entryName: String

    /**
     * All SNI entry strategies have the index in their constructor.
     */
    override fun getObject(): Strategy<Parametrization> {
        return this.javaClass.getDeclaredConstructor(Int::class.java).newInstance(index)
    }
}