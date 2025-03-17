package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.AddSubdomainManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.SubdomainInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Adds a subdomain to the hostname at the given index
 */
@Serializable
class AddSubdomainStrategy(override val index: Int) : EntryStrategy<SubdomainInstantiation>() {
    override val entryName: String
        get() = "AddSubdomain"

    override val strategyEnum: Strategies
        get() = Strategies.ADD_SUBDOMAIN

    override val defaultInstantiation: SubdomainInstantiation
        get() = SubdomainInstantiation.NONE

    override fun getAllInstantiations(): List<SubdomainInstantiation> {
        return SubdomainInstantiation.entries
    }

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            SubdomainInstantiation.NONE -> listOf()
            else -> listOf(AddSubdomainManipulation(index, this.instantiation!!.subdomain))
        }
    }
}