package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.record.RecordInjectionManipulation
import de.rub.nds.censor.core.constants.RecordManipulationType
import de.rub.nds.censor.fuzzer.combination.instantiation.RecordInjectionInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Strategy for injecting records
 */
@Serializable
class RecordInjectionStrategy : Strategy<RecordInjectionInstantiation>() {
    override val defaultInstantiation: RecordInjectionInstantiation
        get() = RecordInjectionInstantiation.NONE

    override val name: String
        get() = "RecordInjection"

    override val strategyEnum: Strategies
        get() = Strategies.RECORD_INJECTION

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            RecordInjectionInstantiation.NONE -> listOf()
            RecordInjectionInstantiation.BEFORE_INVALID_TYPE -> listOf(RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.INVALID_TYPE))
            RecordInjectionInstantiation.BEFORE_CCS_VALID -> listOf(RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.CHANGE_CIPHER_SPEC_VALID))
            RecordInjectionInstantiation.BEFORE_CCS_INVALID -> listOf(RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID))
            RecordInjectionInstantiation.BEFORE_ALERT_INCOMPLETE -> listOf(RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.ALERT_INCOMPLETE))
            RecordInjectionInstantiation.BEFORE_ALERT_INTERNAL_WARN -> listOf(
                RecordInjectionManipulation(
                    recordTypeBefore = RecordManipulationType.ALERT_INTERNAL_WARN
                )
            )

            RecordInjectionInstantiation.BEFORE_ALERT_INTERNAL_FATAL -> listOf(
                RecordInjectionManipulation(
                    recordTypeBefore = RecordManipulationType.ALERT_INTERNAL_FATAL
                )
            )

            RecordInjectionInstantiation.BEFORE_HANDSHAKE_NULL_BYTE -> listOf(
                RecordInjectionManipulation(
                    recordTypeBefore = RecordManipulationType.HANDSHAKE_NULL_BYTE
                )
            )

            RecordInjectionInstantiation.BEFORE_APPLICATION_DATA_NULL_BYTE -> listOf(
                RecordInjectionManipulation(
                    recordTypeBefore = RecordManipulationType.APPLICATION_DATA_NULL_BYTE
                )
            )

            RecordInjectionInstantiation.BEFORE_HEARTBEAT_REQUEST -> listOf(RecordInjectionManipulation(recordTypeBefore = RecordManipulationType.HEARTBEAT_REQUEST))
            RecordInjectionInstantiation.BEFORE_HEARTBEAT_RESPONSE -> listOf(
                RecordInjectionManipulation(
                    recordTypeBefore = RecordManipulationType.HEARTBEAT_RESPONSE
                )
            )

            RecordInjectionInstantiation.BEFORE_HEARTBEAT_INCOMPLETE -> listOf(
                RecordInjectionManipulation(
                    recordTypeBefore = RecordManipulationType.HEARTBEAT_INCOMPLETE
                )
            )

            RecordInjectionInstantiation.AFTER_INVALID_TYPE -> listOf(RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.INVALID_TYPE))
            RecordInjectionInstantiation.AFTER_CCS_VALID -> listOf(RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.CHANGE_CIPHER_SPEC_VALID))
            RecordInjectionInstantiation.AFTER_CCS_INVALID -> listOf(RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID))
            RecordInjectionInstantiation.AFTER_ALERT_INCOMPLETE -> listOf(RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.ALERT_INCOMPLETE))
            RecordInjectionInstantiation.AFTER_ALERT_INTERNAL_WARN -> listOf(RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.ALERT_INTERNAL_WARN))
            RecordInjectionInstantiation.AFTER_ALERT_INTERNAL_FATAL -> listOf(
                RecordInjectionManipulation(
                    recordTypeAfter = RecordManipulationType.ALERT_INTERNAL_FATAL
                )
            )

            RecordInjectionInstantiation.AFTER_HANDSHAKE_NULL_BYTE -> listOf(RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.HANDSHAKE_NULL_BYTE))
            RecordInjectionInstantiation.AFTER_APPLICATION_DATA_NULL_BYTE -> listOf(
                RecordInjectionManipulation(
                    recordTypeAfter = RecordManipulationType.APPLICATION_DATA_NULL_BYTE
                )
            )

            RecordInjectionInstantiation.AFTER_HEARTBEAT_REQUEST -> listOf(RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.HEARTBEAT_REQUEST))
            RecordInjectionInstantiation.AFTER_HEARTBEAT_RESPONSE -> listOf(RecordInjectionManipulation(recordTypeAfter = RecordManipulationType.HEARTBEAT_RESPONSE))
            RecordInjectionInstantiation.AFTER_HEARTBEAT_INCOMPLETE -> listOf(
                RecordInjectionManipulation(
                    recordTypeAfter = RecordManipulationType.HEARTBEAT_INCOMPLETE
                )
            )
        }
    }

    override fun getAllInstantiations(): List<RecordInjectionInstantiation> {
        return RecordInjectionInstantiation.entries
    }
}