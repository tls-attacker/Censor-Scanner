package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.OverrideExtensionTypeManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.ExtensionTypeInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import kotlinx.serialization.Serializable

@Serializable
class ExtensionTypeStrategy : Strategy<ExtensionTypeInstantiation>() {

    override val defaultInstantiation: ExtensionTypeInstantiation
        get() = ExtensionTypeInstantiation.DEFAULT

    override val name: String
        get() = "ExtensionBytes"

    override val strategyEnum: Strategies
        get() = Strategies.EXTENSION_TYPE

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            ExtensionTypeInstantiation.DEFAULT -> listOf()
            ExtensionTypeInstantiation.WRONG0x9999 -> listOf(
                OverrideExtensionTypeManipulation(
                    ServerNameIndicationExtensionMessage::class.java,
                    ExtensionTypeInstantiation.WRONG0x9999.extensionBytes
                )
            )
        }
    }

    override fun getAllInstantiations(): List<ExtensionTypeInstantiation> {
        return ExtensionTypeInstantiation.entries
    }
}