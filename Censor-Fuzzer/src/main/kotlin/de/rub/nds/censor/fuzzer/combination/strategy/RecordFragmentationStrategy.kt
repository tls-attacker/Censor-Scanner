package de.rub.nds.censor.fuzzer.combination.strategy

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.record.RecordFragmentationManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.record.RecordFragmentationPoint
import de.rub.nds.censor.core.constants.RecordManipulationType
import de.rub.nds.censor.fuzzer.combination.instantiation.RecordFragmentationInstantiation
import de.rub.nds.censor.fuzzer.constants.Strategies
import kotlinx.serialization.Serializable

/**
 * Strategy for applying record fragmentation at specific RecordFragmentationPoints
 */
@Serializable
class RecordFragmentationStrategy : Strategy<RecordFragmentationInstantiation>() {
    override val defaultInstantiation: RecordFragmentationInstantiation
        get() = RecordFragmentationInstantiation.NONE

    override val name: String
        get() = "RecordFragmentation"

    override val strategyEnum: Strategies
        get() = Strategies.RECORD_FRAGMENTATION

    override fun getManipulations(): List<TlsManipulation> {
        return when (this.instantiation!!) {
            RecordFragmentationInstantiation.NONE -> listOf()

            RecordFragmentationInstantiation.IN_MESSAGE_HEADER_NONE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_MESSAGE_HEADER
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_NONE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_NONE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_NONE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_INVALID -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.INVALID_TYPE
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_INVALID -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.INVALID_TYPE
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_INVALID -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.INVALID_TYPE
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_CCS_VALID -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.CHANGE_CIPHER_SPEC_VALID
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_CCS_VALID -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.CHANGE_CIPHER_SPEC_VALID
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_CCS_VALID -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.CHANGE_CIPHER_SPEC_VALID
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_CCS_INVALID -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_CCS_INVALID -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_CCS_INVALID -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_ALERT_INCOMPLETE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.ALERT_INCOMPLETE
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_ALERT_INCOMPLETE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.ALERT_INCOMPLETE
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_ALERT_INCOMPLETE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.ALERT_INCOMPLETE
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_ALERT_INTERNAL_WARN -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.ALERT_INTERNAL_WARN
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_ALERT_INTERNAL_WARN -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.ALERT_INTERNAL_WARN
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_ALERT_INTERNAL_WARN -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.ALERT_INTERNAL_WARN
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_ALERT_INTERNAL_FATAL -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.ALERT_INTERNAL_FATAL
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_ALERT_INTERNAL_FATAL -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.ALERT_INTERNAL_FATAL
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_ALERT_INTERNAL_FATAL -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.ALERT_INTERNAL_FATAL
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_HANDSHAKE_NULL_BYTE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.HANDSHAKE_NULL_BYTE
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_HANDSHAKE_NULL_BYTE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.HANDSHAKE_NULL_BYTE
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_HANDSHAKE_NULL_BYTE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.HANDSHAKE_NULL_BYTE
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_APPLICATION_DATA_NULL_BYTE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.APPLICATION_DATA_NULL_BYTE
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_APPLICATION_DATA_NULL_BYTE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.APPLICATION_DATA_NULL_BYTE
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_APPLICATION_DATA_NULL_BYTE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.APPLICATION_DATA_NULL_BYTE
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_HEARTBEAT_REQUEST -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.HEARTBEAT_REQUEST
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_HEARTBEAT_REQUEST -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.HEARTBEAT_REQUEST
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_HEARTBEAT_REQUEST -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.HEARTBEAT_REQUEST
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_HEARTBEAT_RESPONSE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.HEARTBEAT_RESPONSE
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_HEARTBEAT_RESPONSE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.HEARTBEAT_RESPONSE
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_HEARTBEAT_RESPONSE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.HEARTBEAT_RESPONSE
                )
            )

            RecordFragmentationInstantiation.BEFORE_SNI_HEARTBEAT_INCOMPLETE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.BEFORE_SNI,
                    RecordManipulationType.HEARTBEAT_INCOMPLETE
                )
            )

            RecordFragmentationInstantiation.IN_HOSTNAME_HEARTBEAT_INCOMPLETE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.IN_HOSTNAME,
                    RecordManipulationType.HEARTBEAT_INCOMPLETE
                )
            )

            RecordFragmentationInstantiation.AFTER_SNI_HEARTBEAT_INCOMPLETE -> listOf(
                RecordFragmentationManipulation(
                    RecordFragmentationPoint.AFTER_SNI,
                    RecordManipulationType.HEARTBEAT_INCOMPLETE
                )
            )
        }
    }

    override fun getAllInstantiations(): List<RecordFragmentationInstantiation> {
        return RecordFragmentationInstantiation.entries
    }
}