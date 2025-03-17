package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.version.TlsVersionManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.VersionInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

@Serializable
class VersionStrategy : Strategy<VersionInstantiation>() {

    override val defaultInstantiation: VersionInstantiation
        get() = VersionInstantiation.TLS12

    override val name: String
        get() = "TlsVersion"

    override val strategyEnum: Strategies
        get() = Strategies.VERSION

    override fun getManipulations(): List<TlsManipulation> {
        return listOf(TlsVersionManipulation(instantiation!!.protocolVersion))
    }

    override fun getAllInstantiations(): List<VersionInstantiation> {
        return listOf(
            VersionInstantiation.TLS13,
            VersionInstantiation.TLS12,
            VersionInstantiation.TLS11,
            VersionInstantiation.TLS10
        )
    }
}