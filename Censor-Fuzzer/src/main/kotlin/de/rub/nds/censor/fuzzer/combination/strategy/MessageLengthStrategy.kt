package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.message.length.*
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.fuzzer.combination.instantiation.ExtensionsLengthInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import kotlinx.serialization.Serializable

/**
 * Strategy for modifying the length bytes of the CH message.
 */
@Serializable
class MessageLengthStrategy(var correctHostname: String) : Strategy<ExtensionsLengthInstantiation>() {
    override val defaultInstantiation: ExtensionsLengthInstantiation
        get() = ExtensionsLengthInstantiation.CORRECT

    override val name: String
        get() = "MessageLength"

    override val strategyEnum: Strategies
        get() = Strategies.MESSAGE_LENGTH

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            ExtensionsLengthInstantiation.CORRECT -> listOf()
            ExtensionsLengthInstantiation.STRIP_LAST_EXT -> listOf(MessageLengthStripLastExtensionManipulation())
            ExtensionsLengthInstantiation.DEFAULT -> listOf(
                MessageLengthOnlyDefaultFirstSniEntryManipulation(
                    correctHostname
                )
            )

            ExtensionsLengthInstantiation.ONLY_FIRST_SNI -> listOf(MessageLengthOnlyFirstSniEntryManipulation())
            ExtensionsLengthInstantiation.GARBAGE_BYTES -> listOf(
                MessageLengthTooLongGarbageManipulation(
                    20,
                    CoreClientHelloMessage::class.java
                )
            )

            ExtensionsLengthInstantiation.MAX -> listOf(
                MessageLengthManipulation(
                    MAXIMUM_2_BYTE_FIELD_VALUE.toDouble(),
                    CoreClientHelloMessage::class.java
                )
            )

            ExtensionsLengthInstantiation.ZERO -> listOf(
                MessageLengthManipulation(
                    0.0,
                    CoreClientHelloMessage::class.java
                )
            )

            ExtensionsLengthInstantiation.HALF -> listOf(
                MessageLengthManipulation(
                    0.5,
                    CoreClientHelloMessage::class.java
                )
            )

            ExtensionsLengthInstantiation.DOUBLE -> listOf(
                MessageLengthManipulation(
                    2.0,
                    CoreClientHelloMessage::class.java
                )
            )
        }
    }

    override fun getAllInstantiations(): List<ExtensionsLengthInstantiation> {
        return ExtensionsLengthInstantiation.entries
    }

    override fun getObject(): Strategy<ExtensionsLengthInstantiation> {
        return this.javaClass.getDeclaredConstructor(String::class.java).newInstance(correctHostname)
    }
}