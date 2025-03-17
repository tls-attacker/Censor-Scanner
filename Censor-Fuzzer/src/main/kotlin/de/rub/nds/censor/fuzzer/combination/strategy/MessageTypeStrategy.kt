package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.message.MessageTypeManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.MessageTypeInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import kotlinx.serialization.Serializable

@Serializable
class MessageTypeStrategy: Strategy<MessageTypeInstantiation>() {
    override val defaultInstantiation: MessageTypeInstantiation
        get() = MessageTypeInstantiation.CLIENT_HELLO
    override val name: String
        get() = "MessageType"
    override val strategyEnum: Strategies
        get() = Strategies.MESSAGE_TYPE

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            MessageTypeInstantiation.CLIENT_HELLO -> listOf()
            else -> listOf(MessageTypeManipulation(this.instantiation!!.messageType.value, ClientHelloMessage::class.java))
        }
    }

    override fun getAllInstantiations(): List<MessageTypeInstantiation> {
        return MessageTypeInstantiation.entries
    }
}