package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.message.MessageVersionManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.VersionInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import kotlinx.serialization.Serializable

/**
 * Strategy that modifies the version directly in the ClientHelloMessage
 */
@Serializable
class MessageVersionStrategy : Strategy<VersionInstantiation>() {
    override val defaultInstantiation: VersionInstantiation
        get() = VersionInstantiation.DEFAULT

    override val name: String
        get() = "MessageVersion"

    override val strategyEnum: Strategies
        get() = Strategies.MESSAGE_VERSION

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            VersionInstantiation.DEFAULT -> listOf()
            else -> listOf(MessageVersionManipulation(this.instantiation!!.newVersion, ClientHelloMessage::class.java))
        }
    }

    override fun getAllInstantiations(): List<VersionInstantiation> {
        return VersionInstantiation.entries
    }
}