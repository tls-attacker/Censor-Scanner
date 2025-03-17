package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.record.RecordContentTypeManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.RecordContentTypeInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import kotlinx.serialization.Serializable

/**
 * Strategy for modifying the content type of TLS records
 */
@Serializable
class RecordContentTypeStrategy : Strategy<RecordContentTypeInstantiation>() {
    override val defaultInstantiation: RecordContentTypeInstantiation
        get() = RecordContentTypeInstantiation.HANDSHAKE

    override val name: String
        get() = "RecordContentType"

    override val strategyEnum: Strategies
        get() = Strategies.RECORD_CONTENT_TYPE

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            RecordContentTypeInstantiation.HANDSHAKE -> listOf()
            else -> listOf(
                RecordContentTypeManipulation(
                    this.instantiation!!.messageType,
                    ProtocolMessageType.HANDSHAKE
                )
            )
        }
    }

    override fun getAllInstantiations(): List<RecordContentTypeInstantiation> {
        return RecordContentTypeInstantiation.entries
    }
}