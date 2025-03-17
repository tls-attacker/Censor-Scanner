package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.AdditionalEntryManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.MaxAdditionalEntryManipulationWithThreeCorrect
import de.rub.nds.censor.core.connection.manipulation.tls.sni.StripListEntriesManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.AdditionalEntriesInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

@Serializable
class SniEntriesStrategy(val harmlessHostname: String, var originalHostname: String) :
    Strategy<AdditionalEntriesInstantiation>() {

    override val defaultInstantiation: AdditionalEntriesInstantiation
        get() = AdditionalEntriesInstantiation.ONE
    override val name: String
        get() = "AdditionalEntries"

    override val strategyEnum: Strategies
        get() = Strategies.ADDITIONAL_ENTRIES

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            // remove entry
            AdditionalEntriesInstantiation.NONE -> listOf(StripListEntriesManipulation())
            // add one additional entry
            AdditionalEntriesInstantiation.ONE -> listOf()
            // add maximum number of additional entries
            AdditionalEntriesInstantiation.TWO -> listOf(AdditionalEntryManipulation(originalHostname, 1))
            AdditionalEntriesInstantiation.THREE -> listOf(AdditionalEntryManipulation(originalHostname, 2))
            AdditionalEntriesInstantiation.MAX -> listOf(
                MaxAdditionalEntryManipulationWithThreeCorrect(
                    correctHostname = originalHostname,
                    incorrectHostname = harmlessHostname
                )
            )
        }
    }


    override fun getAllInstantiations(): List<AdditionalEntriesInstantiation> {
        return AdditionalEntriesInstantiation.entries
    }

    override fun getObject(): Strategy<AdditionalEntriesInstantiation> {
        return this.javaClass.getDeclaredConstructor(String::class.java, String::class.java)
            .newInstance(harmlessHostname, originalHostname)
    }

    fun getListIndicesToInstantiateForManipulation(): List<Int> {
        return when (this.instantiation!!) {
            AdditionalEntriesInstantiation.NONE -> listOf()
            AdditionalEntriesInstantiation.ONE -> listOf(0)
            AdditionalEntriesInstantiation.TWO -> listOf(0, 1)
            AdditionalEntriesInstantiation.THREE -> listOf(0, 1, 2)
            AdditionalEntriesInstantiation.MAX -> listOf(0, Int.MAX_VALUE, -1)
        }
    }
}