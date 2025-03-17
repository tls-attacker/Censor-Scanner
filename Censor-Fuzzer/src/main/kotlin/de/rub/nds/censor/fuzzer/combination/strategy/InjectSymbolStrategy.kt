package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.InjectSymbolsManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.InjectSymbolInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Injects a symbol before, in the middle of, or after hostname for the given index.
 */
@Serializable
class InjectSymbolStrategy(override val index: Int, var hostnameLength: Int) :
    EntryStrategy<InjectSymbolInstantiation>() {
    override val entryName: String
        get() = "InjectSymbol"

    override val strategyEnum: Strategies
        get() = Strategies.INJECT_SYMBOL

    override val defaultInstantiation: InjectSymbolInstantiation
        get() = InjectSymbolInstantiation.NONE

    override fun getAllInstantiations(): List<InjectSymbolInstantiation> {
        return InjectSymbolInstantiation.entries
    }

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            InjectSymbolInstantiation.NONE -> listOf()
            InjectSymbolInstantiation.BEFORE_00 -> listOf(InjectSymbolsManipulation(index, 0, byteArrayOf(0x00)))
            InjectSymbolInstantiation.MIDDLE_00 -> listOf(
                InjectSymbolsManipulation(
                    index,
                    hostnameLength / 2,
                    byteArrayOf(0x00)
                )
            )

            InjectSymbolInstantiation.AFTER_00 -> listOf(
                InjectSymbolsManipulation(
                    index,
                    hostnameLength,
                    byteArrayOf(0x00)
                )
            )

            InjectSymbolInstantiation.BEFORE_SPACE -> listOf(InjectSymbolsManipulation(index, 0, byteArrayOf(0x20)))
            InjectSymbolInstantiation.MIDDLE_SPACE -> listOf(
                InjectSymbolsManipulation(
                    index,
                    hostnameLength / 2,
                    byteArrayOf(0x20)
                )
            )

            InjectSymbolInstantiation.AFTER_SPACE -> listOf(
                InjectSymbolsManipulation(
                    index,
                    hostnameLength,
                    byteArrayOf(0x20)
                )
            )

            InjectSymbolInstantiation.BEFORE_BACKSPACE -> listOf(
                InjectSymbolsManipulation(
                    index,
                    0,
                    byteArrayOf(0x71, 0x08)
                )
            )

            InjectSymbolInstantiation.MIDDLE_BACKSPACE -> listOf(
                InjectSymbolsManipulation(
                    index,
                    hostnameLength / 2,
                    byteArrayOf(0x71, 0x08)
                )
            )

            InjectSymbolInstantiation.AFTER_BACKSPACE -> listOf(
                InjectSymbolsManipulation(
                    index,
                    hostnameLength,
                    byteArrayOf(0x71, 0x08)
                )
            )

            InjectSymbolInstantiation.BEFORE_LEFT_TO_RIGHT_UNICODE -> listOf(
                InjectSymbolsManipulation(
                    index,
                    0,
                    byteArrayOf(0xE2.toByte(), 0x80.toByte(), 0x8E.toByte())
                )
            )

            InjectSymbolInstantiation.MIDDLE_LEFT_TO_RIGHT_UNICODE -> listOf(
                InjectSymbolsManipulation(
                    index,
                    hostnameLength / 2,
                    byteArrayOf(0xE2.toByte(), 0x80.toByte(), 0x8E.toByte())
                )
            )

            InjectSymbolInstantiation.AFTER_LEFT_TO_RIGHT_UNICODE -> listOf(
                InjectSymbolsManipulation(
                    index,
                    hostnameLength,
                    byteArrayOf(0xE2.toByte(), 0x80.toByte(), 0x8E.toByte())
                )
            )

            InjectSymbolInstantiation.AFTER_INCOMPLETE_UNICODE -> listOf(
                InjectSymbolsManipulation(
                    index,
                    hostnameLength,
                    byteArrayOf(0xE1.toByte())
                )
            )
        }
    }

    override fun getObject(): Strategy<InjectSymbolInstantiation> {
        return this.javaClass.getDeclaredConstructor(Int::class.java, Int::class.java)
            .newInstance(index, hostnameLength)
    }
}