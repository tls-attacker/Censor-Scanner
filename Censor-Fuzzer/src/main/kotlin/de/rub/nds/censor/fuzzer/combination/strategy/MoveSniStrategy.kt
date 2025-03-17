package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.message.MoveSniManipulation
import de.rub.nds.censor.fuzzer.combination.instantiation.MoveSniInstantiations
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Strategy for moving the SNI extension in the message to a new position
 */
@Serializable
class MoveSniStrategy : Strategy<MoveSniInstantiations>() {
    override val defaultInstantiation: MoveSniInstantiations
        get() = MoveSniInstantiations.CORRECT

    override val name: String
        get() = "MoveSNI"

    override val strategyEnum: Strategies
        get() = Strategies.MOVE_SNI

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            MoveSniInstantiations.CORRECT -> listOf()
            else -> listOf(MoveSniManipulation(this.instantiation!!.position))
        }
    }

    override fun getAllInstantiations(): List<MoveSniInstantiations> {
        return MoveSniInstantiations.entries
    }
}