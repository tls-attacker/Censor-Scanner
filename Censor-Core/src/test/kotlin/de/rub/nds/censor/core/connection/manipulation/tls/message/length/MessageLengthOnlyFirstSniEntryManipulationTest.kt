package de.rub.nds.censor.core.connection.manipulation.tls.message.length

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.AdditionalEntryManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.OverrideHostnameManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants
import de.rub.nds.censor.core.constants.ManipulationConstants.HANDSHAKE_TYPE_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.RECORD_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_NAME_LENGTH_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_NAME_TYPE_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSION_HEADER
import de.rub.nds.censor.core.util.Util.toHexString

class MessageLengthOnlyFirstSniEntryManipulationTest: SniTest<MessageLengthOnlyFirstSniEntryManipulation>(fails = true) {
    override fun extraManipulations(): Collection<TlsManipulation> {
        return  super.extraManipulations() +
                AdditionalEntryManipulation(DEFAULT_TEST_HOSTNAME, 1) +
                OverrideHostnameManipulation(0, DEFAULT_TEST_REPLACEMENT_HOSTNAME) // necessary because else it is already default
    }
    override fun targetManipulations(): Collection<MessageLengthOnlyFirstSniEntryManipulation> {
        return listOf(
            MessageLengthOnlyFirstSniEntryManipulation()
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: MessageLengthOnlyFirstSniEntryManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // check correct modification and all super lengths remain the same after manipulations
        val correctExtensionsLength = defaultEcPointFormatsExtensionLength + defaultSupportedGroupsExtensionLength + 2 * TLS_EXTENSION_HEADER +
                DEFAULT_TEST_REPLACEMENT_HOSTNAME.length + ManipulationConstants.SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
        val correctMessageLength = (ManipulationConstants.MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN + correctExtensionsLength).toHexString(MESSAGE_LENGTH_SIZE)
        val correctRecordLength = (HANDSHAKE_TYPE_SIZE + MESSAGE_LENGTH_SIZE + defaultMessageLength + DEFAULT_TEST_REPLACEMENT_HOSTNAME.length + SNI_NAME_TYPE_LENGTH + SNI_NAME_LENGTH_LENGTH).toHexString(
            RECORD_LENGTH_SIZE)

        assert(actual.contains("160303" + correctRecordLength + "01" + correctMessageLength + "0303", ignoreCase = true))
    }
}