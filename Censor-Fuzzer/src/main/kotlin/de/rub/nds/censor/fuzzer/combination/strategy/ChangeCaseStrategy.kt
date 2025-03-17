package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.SpongebobCaseManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.CaseInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Changes the case of the hostname at the given index
 */
@Serializable
class ChangeCaseStrategy(override val index: Int) : EntryStrategy<CaseInstantiation>() {
    override val entryName: String
        get() = "ChangeCase"

    override val strategyEnum: Strategies
        get() = Strategies.CHANGE_CASE

    override val defaultInstantiation: CaseInstantiation
        get() = CaseInstantiation.DEFAULT

    override fun getAllInstantiations(): List<CaseInstantiation> {
        return CaseInstantiation.entries
    }

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            CaseInstantiation.DEFAULT -> listOf()
            CaseInstantiation.ALTERNATING_CASES -> listOf(SpongebobCaseManipulation(index))
        }
    }
}