package de.rub.nds.censor.core.connection.manipulation.tls.message.length

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE
import de.rub.nds.censor.core.util.IntegerMultiplyWithMaximumModification
import de.rub.nds.modifiablevariable.ModifiableVariableFactory
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage
import de.rub.nds.tlsattacker.core.state.State
import de.rub.nds.tlsattacker.core.workflow.action.SendAction

/**
 * Modifies the length of a TLS message.
 */
class MessageLengthManipulation(val messageLengthModifier: Double, private val messageType: Class<out HandshakeMessage>): TlsManipulation() {

    override val name: String
        get() = "message_length(messageLengthModifier=$messageLengthModifier, messageType=$messageType)"


    override fun afterStateGeneration(state: State) {
        val incorrectMessageLengthModification = IntegerMultiplyWithMaximumModification(messageLengthModifier, MAXIMUM_2_BYTE_FIELD_VALUE)
        // create modification and add afterward

        // set message length of selected handshakes messages
        state.workflowTrace.sendingActions.filterIsInstance<SendAction>().forEach { messageAction ->
            messageAction.configuredMessages?.forEach { message ->
                if (messageType.isInstance(message)) {
                    val castedMessage = message as HandshakeMessage
                    castedMessage.length = ModifiableVariableFactory.createIntegerModifiableVariable()
                    castedMessage.length.modification = incorrectMessageLengthModification
                }
            }
        }
    }
}