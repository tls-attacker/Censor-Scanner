package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.AdditionalSniExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.RemoveSniExtensionsManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.AdditionalSniInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

@Serializable
class AdditionalSniStrategy(private val hostname: String) : Strategy<AdditionalSniInstantiation>() {
    override val defaultInstantiation: AdditionalSniInstantiation
        get() = AdditionalSniInstantiation.NONE
    override val name: String
        get() = "AdditionalSni"
    override val strategyEnum: Strategies
        get() = Strategies.ADDITIONAL_ENTRIES

    override fun getManipulations(): List<TlsManipulation> {
        return when (instantiation!!) {
            AdditionalSniInstantiation.REMOVE -> listOf(RemoveSniExtensionsManipulation())
            AdditionalSniInstantiation.NONE -> listOf()
            AdditionalSniInstantiation.FIRST -> listOf(
                AdditionalSniExtensionManipulation(
                    place = 0,
                    hostname = hostname
                )
            )

            AdditionalSniInstantiation.LAST -> listOf(
                AdditionalSniExtensionManipulation(
                    place = -1,
                    hostname = hostname
                )
            )
        }
    }

    override fun getAllInstantiations(): List<AdditionalSniInstantiation> {
        return AdditionalSniInstantiation.entries
    }

    override fun getObject(): Strategy<AdditionalSniInstantiation> {
        return this.javaClass.getDeclaredConstructor(String::class.java).newInstance(hostname)
    }
}