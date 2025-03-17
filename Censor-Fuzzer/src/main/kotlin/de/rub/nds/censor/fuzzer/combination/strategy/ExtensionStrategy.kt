package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.EchExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.EsniExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.constants.EncryptedClientHelloVersion
import de.rub.nds.censor.fuzzer.combination.instantiation.ExtensionInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

@Serializable
class ExtensionStrategy(var hostname: String) : Strategy<ExtensionInstantiation>() {

    override val defaultInstantiation: ExtensionInstantiation
        get() = ExtensionInstantiation.SNI

    override val name: String
        get() = "Extension"

    override val strategyEnum: Strategies
        get() = Strategies.EXTENSION

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            ExtensionInstantiation.NONE -> listOf(SniExtensionManipulation(hostname, false))

            ExtensionInstantiation.SNI -> listOf(SniExtensionManipulation(hostname, true))

            ExtensionInstantiation.ESNI -> listOf(EsniExtensionManipulation(enable = true))

            ExtensionInstantiation.ECH7 -> listOf(
                EchExtensionManipulation(
                    hostname,
                    EncryptedClientHelloVersion.DRAFT_07,
                    enable = true
                )
            )

            ExtensionInstantiation.ECH13 -> listOf(
                EchExtensionManipulation(
                    hostname,
                    EncryptedClientHelloVersion.DRAFT_13_14_15_16_17,
                    enable = true
                )
            )

            ExtensionInstantiation.SNI_ESNI -> listOf(
                SniExtensionManipulation(hostname, true),
                EsniExtensionManipulation(enable = true)
            )

            ExtensionInstantiation.SNI_ECH7 -> listOf(
                SniExtensionManipulation(hostname, true),
                EchExtensionManipulation(hostname, EncryptedClientHelloVersion.DRAFT_07, enable = true)
            )

            ExtensionInstantiation.SNI_ECH13 -> listOf(
                SniExtensionManipulation(hostname, true),
                EchExtensionManipulation(hostname, EncryptedClientHelloVersion.DRAFT_13_14_15_16_17, enable = true)
            )

            ExtensionInstantiation.ESNI_ECH7 -> listOf(
                EsniExtensionManipulation(enable = true),
                EchExtensionManipulation(hostname, EncryptedClientHelloVersion.DRAFT_07, enable = true)
            )

            ExtensionInstantiation.ESNI_ECH13 -> listOf(
                EsniExtensionManipulation(enable = true),
                EchExtensionManipulation(hostname, EncryptedClientHelloVersion.DRAFT_13_14_15_16_17, enable = true)
            )

            ExtensionInstantiation.SNI_ESNI_ECH7 -> listOf(
                SniExtensionManipulation(hostname, true),
                EsniExtensionManipulation(enable = true),
                EchExtensionManipulation(hostname, EncryptedClientHelloVersion.DRAFT_07, enable = true)
            )

            ExtensionInstantiation.SNI_ESNI_ECH13 -> listOf(
                SniExtensionManipulation(hostname, true),
                EsniExtensionManipulation(enable = true),
                EchExtensionManipulation(hostname, EncryptedClientHelloVersion.DRAFT_13_14_15_16_17, enable = true)
            )

        }
    }

    override fun getAllInstantiations(): List<ExtensionInstantiation> {
        return ExtensionInstantiation.entries
    }

    override fun getObject(): Strategy<ExtensionInstantiation> {
        return ExtensionStrategy(hostname)
    }
}