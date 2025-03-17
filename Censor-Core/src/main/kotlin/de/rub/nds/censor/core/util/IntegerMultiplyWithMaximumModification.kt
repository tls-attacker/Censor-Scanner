package de.rub.nds.censor.core.util

import de.rub.nds.modifiablevariable.VariableModification
import java.util.*

/**
 * Modification that multiplies an integer with a value but considers a maximum value.
 */
class IntegerMultiplyWithMaximumModification(private val multiplier: Double, private val maximum: Int) :
    VariableModification<Int?>() {

    override fun modifyImplementationHook(input: Int?): Int {
        return input?.times(multiplier)?.coerceAtMost(maximum.toDouble())?.toInt() ?: 0
    }

    override fun getModifiedCopy(): VariableModification<Int?> {
        throw NotImplementedError()
    }

    override fun hashCode(): Int {
        var hash = 7
        hash = 53 * hash + Objects.hashCode(multiplier)
        return hash
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other == null) {
            return false
        }
        if (javaClass != other.javaClass) {
            return false
        }
        return Objects.equals(multiplier, (other as IntegerMultiplyWithMaximumModification).multiplier)
    }
}