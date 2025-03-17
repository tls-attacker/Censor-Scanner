package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list.ListLengthManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list.ListLengthOnlyDefaultFirstSniEntryManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list.ListLengthOnlyFirstSniEntryManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list.ListLengthTooLongGarbageManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.fuzzer.combination.instantiation.LengthInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Strategy for modifying the length bytes of the list in the SNI extension.
 */
@Serializable
class ListLengthStrategy(var correctHostname: String) : Strategy<LengthInstantiation>() {
    override val defaultInstantiation: LengthInstantiation
        get() = LengthInstantiation.CORRECT

    override val name: String
        get() = "ListLength"

    override val strategyEnum: Strategies
        get() = Strategies.LIST_LENGTH

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            LengthInstantiation.CORRECT -> listOf()
            LengthInstantiation.DEFAULT -> listOf(ListLengthOnlyDefaultFirstSniEntryManipulation(correctHostname))
            LengthInstantiation.ONLY_FIRST_SNI -> listOf(ListLengthOnlyFirstSniEntryManipulation())
            LengthInstantiation.GARBAGE_BYTES -> listOf(ListLengthTooLongGarbageManipulation(20))
            LengthInstantiation.DOUBLE -> listOf(ListLengthManipulation(2.0))
            LengthInstantiation.HALF -> listOf(ListLengthManipulation(0.5))
            LengthInstantiation.ZERO -> listOf(ListLengthManipulation(0.0))
            LengthInstantiation.MAX -> listOf(ListLengthManipulation(MAXIMUM_2_BYTE_FIELD_VALUE.toDouble()))
        }
    }

    override fun getAllInstantiations(): List<LengthInstantiation> {
        return LengthInstantiation.entries
    }

    override fun getObject(): Strategy<LengthInstantiation> {
        return this.javaClass.getDeclaredConstructor(String::class.java).newInstance(correctHostname)
    }
}