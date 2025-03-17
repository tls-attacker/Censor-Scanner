package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.record.RecordVersionManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.VersionInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import kotlinx.serialization.Serializable

/**
 * Strategy for modifying the protocol version in TLS records
 */
@Serializable
class RecordVersionStrategy : Strategy<VersionInstantiation>() {
    override val defaultInstantiation: VersionInstantiation
        get() = VersionInstantiation.DEFAULT

    override val name: String
        get() = "RecordVersion"

    override val strategyEnum: Strategies
        get() = Strategies.RECORD_VERSION

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            VersionInstantiation.DEFAULT -> listOf()
            else -> listOf(RecordVersionManipulation(this.instantiation!!.newVersion, ProtocolMessageType.HANDSHAKE))
        }
    }

    override fun getAllInstantiations(): List<VersionInstantiation> {
        return VersionInstantiation.entries
    }
}