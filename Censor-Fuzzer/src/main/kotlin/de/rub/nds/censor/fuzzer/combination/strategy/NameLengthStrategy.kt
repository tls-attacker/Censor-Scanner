package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.NameLengthManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.fuzzer.combination.instantiation.NameLengthInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable


/**
 * Changes the name length of the entry at the given index in the SNI.
 */
@Serializable
class NameLengthStrategy(override val index: Int, var correctLength: Int) :
    EntryStrategy<NameLengthInstantiation>() {
    override val entryName: String
        get() = "NameLength"

    override val strategyEnum: Strategies
        get() = Strategies.NAME_LENGTH

    override val defaultInstantiation: NameLengthInstantiation
        get() = NameLengthInstantiation.CORRECT

    override fun getAllInstantiations(): List<NameLengthInstantiation> {
        return NameLengthInstantiation.entries
    }

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            NameLengthInstantiation.CORRECT -> listOf()
            else -> listOf(NameLengthManipulation(index,
                (correctLength * this.instantiation!!.modifier).coerceAtMost(MAXIMUM_2_BYTE_FIELD_VALUE.toDouble())
                    .toInt()
            )
            )
        }
    }

    override fun getObject(): Strategy<NameLengthInstantiation> {
        return this.javaClass.getDeclaredConstructor(Int::class.java, Int::class.java).newInstance(index, correctLength)
    }
}