package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.NameTypeManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.NameTypeInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Changes the name type of the entry at the given index
 */
@Serializable
class NameTypeStrategy(override val index: Int) : EntryStrategy<NameTypeInstantiation>() {
    override val entryName: String
        get() = "NameType"

    override val strategyEnum: Strategies
        get() = Strategies.NAME_TYPE

    override val defaultInstantiation: NameTypeInstantiation
        get() = NameTypeInstantiation.CORRECT

    override fun getAllInstantiations(): List<NameTypeInstantiation> {
        return NameTypeInstantiation.entries
    }

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            NameTypeInstantiation.CORRECT -> listOf()
            NameTypeInstantiation.INCORRECT -> listOf(NameTypeManipulation(index, 0x01))
        }
    }
}