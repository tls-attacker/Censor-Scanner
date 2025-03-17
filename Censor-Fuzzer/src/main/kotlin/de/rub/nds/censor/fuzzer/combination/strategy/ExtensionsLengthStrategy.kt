package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.length.*
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.fuzzer.combination.instantiation.ExtensionsLengthInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Strategy for modifying the length bytes of the extensions
 */
@Serializable
class ExtensionsLengthStrategy(var correctHostname: String) : Strategy<ExtensionsLengthInstantiation>() {
    override val defaultInstantiation: ExtensionsLengthInstantiation
        get() = ExtensionsLengthInstantiation.CORRECT

    override val name: String
        get() = "ExtensionsLength"

    override val strategyEnum: Strategies
        get() = Strategies.EXTENSIONS_LENGTH

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            ExtensionsLengthInstantiation.CORRECT -> listOf()
            ExtensionsLengthInstantiation.ONLY_FIRST_SNI -> listOf(ExtensionsLengthOnlyFirstSniEntryManipulation())
            ExtensionsLengthInstantiation.DEFAULT -> listOf(
                ExtensionsLengthOnlyDefaultFirstSniEntryManipulation(
                    correctHostname
                )
            )

            ExtensionsLengthInstantiation.STRIP_LAST_EXT -> listOf(ExtensionsLengthStripLastExtensionManipulation())
            ExtensionsLengthInstantiation.GARBAGE_BYTES -> listOf(ExtensionsLengthTooLongGarbageManipulation(20))
            ExtensionsLengthInstantiation.DOUBLE -> listOf(ExtensionsLengthManipulation(2.0))
            ExtensionsLengthInstantiation.HALF -> listOf(ExtensionsLengthManipulation(0.5))
            ExtensionsLengthInstantiation.ZERO -> listOf(ExtensionsLengthManipulation(0.0))
            ExtensionsLengthInstantiation.MAX -> listOf(ExtensionsLengthManipulation(MAXIMUM_2_BYTE_FIELD_VALUE.toDouble()))
        }
    }

    override fun getAllInstantiations(): List<ExtensionsLengthInstantiation> {
        return ExtensionsLengthInstantiation.entries
    }

    override fun getObject(): Strategy<ExtensionsLengthInstantiation> {
        return this.javaClass.getDeclaredConstructor(String::class.java).newInstance(correctHostname)
    }
}