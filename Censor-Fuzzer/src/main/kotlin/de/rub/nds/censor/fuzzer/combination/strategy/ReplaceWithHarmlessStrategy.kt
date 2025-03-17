package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.OverrideHostnameManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.ReplaceWithHarmlessInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Replaces the existing hostname at the index with a harmless one
 */
@Serializable
class ReplaceWithHarmlessStrategy(override val index: Int) : EntryStrategy<ReplaceWithHarmlessInstantiation>() {
    override val defaultInstantiation: ReplaceWithHarmlessInstantiation
        get() = ReplaceWithHarmlessInstantiation.DEFAULT

    override val entryName: String
        get() = "ReplaceWithHarmless"

    override val strategyEnum: Strategies
        get() = Strategies.REPLACE_WITH_HARMLESS

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            ReplaceWithHarmlessInstantiation.DEFAULT -> return listOf()
            ReplaceWithHarmlessInstantiation.HARMLESS -> listOf(OverrideHostnameManipulation(index, HARMLESS_HOSTNAME))
        }
    }

    override fun getAllInstantiations(): List<ReplaceWithHarmlessInstantiation> {
        return ReplaceWithHarmlessInstantiation.entries
    }

    companion object {
        const val HARMLESS_HOSTNAME = "www.rfc-editor.org"
    }
}