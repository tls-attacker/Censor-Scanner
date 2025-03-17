package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.record.RecordLengthManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.RecordLengthInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import kotlinx.serialization.Serializable

/**
 * Strategy for modifying the record length
 */
@Serializable
class RecordLengthStrategy : Strategy<RecordLengthInstantiation>() {
    override val defaultInstantiation: RecordLengthInstantiation
        get() = RecordLengthInstantiation.CORRECT

    override val name: String
        get() = "RecordLength"

    override val strategyEnum: Strategies
        get() = Strategies.RECORD_LENGTH

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            RecordLengthInstantiation.CORRECT -> listOf()
            else -> listOf(RecordLengthManipulation(this.instantiation!!.modifier, ProtocolMessageType.HANDSHAKE))
        }
    }

    override fun getAllInstantiations(): List<RecordLengthInstantiation> {
        return RecordLengthInstantiation.entries
    }
}