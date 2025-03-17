package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.Instantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Abstracts a single strategy which can be combined with others. Parametrization holds a type for instantiations of this strategy. E.g. Int for a strategy that increases a size by x
 */
@Serializable
sealed class Strategy<Parametrization : Instantiation> : Comparable<Strategy<Parametrization>> {

    abstract val defaultInstantiation: Parametrization

    abstract val name: String

    /**
     * Mapping to enum
     */
    abstract val strategyEnum: Strategies

    var instantiation: Parametrization? = null
        get() = field ?: defaultInstantiation

    open fun instantiate(instantiation: Parametrization) {
        this.instantiation = instantiation
    }

    /**
     * Returns all manipulations required for this strategy
     */
    abstract fun getManipulations(): List<TlsManipulation>

    /**
     * Returns all possible instantiations.
     */
    protected abstract fun getAllInstantiations(): List<Parametrization>

    /**
     * Dirty hack for something that should be abstract and static.
     * Returns objects of this class with parametrizations.
     */
    fun instantiateWithAllPossibilities(): List<Strategy<Parametrization>> {
        return getAllInstantiations().map { instantiation ->
            val newStrategy = getObject()
            newStrategy.instantiate(instantiation)
            newStrategy
        }
    }

    /**
     * Dirty hack for something that should be abstract and static.
     * Returns objects of this class with parametrizations except the default one.
     */
    fun instantiateWithAllPossibilitiesExceptDefault(): List<Strategy<Parametrization>> {
        return getAllInstantiations().filter {
            it != defaultInstantiation
        }.map { instantiation ->
            val newStrategy = getObject()
            newStrategy.instantiate(instantiation)
            newStrategy
        }
    }

    /**
     * Returns a new object of this class, override in implementing classes with constructor values
     */
    open fun getObject(): Strategy<Parametrization> {
        return this.javaClass.getDeclaredConstructor().newInstance()
    }

    override fun toString(): String {
        return "$name(instantiation=$instantiation)"
    }

    // TODO: remove? together with precedence, can also be compared over Strategies enum
    /**
     * Compares two strategies such that the order will be
     * Non-SNI strategies -> AdditionalEntriesStrategy -> SNI strategies
     */
    override operator fun compareTo(other: Strategy<Parametrization>): Int {
        return this.strategyEnum.compareTo(other.strategyEnum)
    }
}