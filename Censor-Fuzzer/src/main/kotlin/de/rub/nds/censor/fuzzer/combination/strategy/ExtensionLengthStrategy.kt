package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.length.extension.ExtensionLengthManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.length.extension.ExtensionLengthOnlyDefaultFirstSniEntryManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.length.extension.ExtensionLengthOnlyFirstSniEntryManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.length.extension.ExtensionLengthTooLongGarbageManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.fuzzer.combination.instantiation.LengthInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Strategy for modifying the length bytes of the SNI extension
 */
@Serializable
class ExtensionLengthStrategy(var correctHostname: String) : Strategy<LengthInstantiation>() {
    override val defaultInstantiation: LengthInstantiation
        get() = LengthInstantiation.CORRECT

    override val name: String
        get() = "ExtensionLength"

    override val strategyEnum: Strategies
        get() = Strategies.EXTENSION_LENGTH

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            LengthInstantiation.CORRECT -> listOf()
            LengthInstantiation.ONLY_FIRST_SNI -> listOf(ExtensionLengthOnlyFirstSniEntryManipulation())
            LengthInstantiation.DEFAULT -> listOf(ExtensionLengthOnlyDefaultFirstSniEntryManipulation(correctHostname))
            LengthInstantiation.GARBAGE_BYTES -> listOf(ExtensionLengthTooLongGarbageManipulation(20))
            LengthInstantiation.MAX -> listOf(ExtensionLengthManipulation(MAXIMUM_2_BYTE_FIELD_VALUE.toDouble()))
            LengthInstantiation.ZERO -> listOf(ExtensionLengthManipulation(0.0))
            LengthInstantiation.HALF -> listOf(ExtensionLengthManipulation(0.5))
            LengthInstantiation.DOUBLE -> listOf(ExtensionLengthManipulation(2.0))
        }
    }

    override fun getAllInstantiations(): List<LengthInstantiation> {
        return LengthInstantiation.entries
    }

    override fun getObject(): Strategy<LengthInstantiation> {
        return this.javaClass.getDeclaredConstructor(String::class.java).newInstance(correctHostname)
    }
}