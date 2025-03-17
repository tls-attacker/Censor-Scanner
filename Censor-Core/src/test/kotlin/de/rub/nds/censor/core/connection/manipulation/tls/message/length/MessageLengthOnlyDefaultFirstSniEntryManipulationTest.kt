package de.rub.nds.censor.core.connection.manipulation.tls.message.length

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.OverrideHostnameManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants
import de.rub.nds.censor.core.constants.ManipulationConstants.HANDSHAKE_TYPE_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.RECORD_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSION_HEADER
import de.rub.nds.censor.core.util.Util.toHexString

class MessageLengthOnlyDefaultFirstSniEntryManipulationTest: SniTest<MessageLengthOnlyDefaultFirstSniEntryManipulation>(fails = true) {
    override fun extraManipulations(): Collection<TlsManipulation> {
        return super.extraManipulations() +
                OverrideHostnameManipulation(0, DEFAULT_TEST_REPLACEMENT_HOSTNAME) // necessary because else it is already default
    }
    override fun targetManipulations(): Collection<MessageLengthOnlyDefaultFirstSniEntryManipulation> {
        return listOf(
            MessageLengthOnlyDefaultFirstSniEntryManipulation(DEFAULT_TEST_HOSTNAME)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: MessageLengthOnlyDefaultFirstSniEntryManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // check correct modification and all super lengths remain the same after manipulations
        val correctExtensionsLength = defaultEcPointFormatsExtensionLength + defaultSupportedGroupsExtensionLength + 2 * TLS_EXTENSION_HEADER +
                DEFAULT_TEST_HOSTNAME.length + SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
        val correctMessageLength = (MESSAGE_LENGTH_OFFSET_FROM_EXTENSIONS_LEN + correctExtensionsLength).toHexString(MESSAGE_LENGTH_SIZE)
        val correctRecordLength = (HANDSHAKE_TYPE_SIZE + MESSAGE_LENGTH_SIZE + defaultMessageLength + (DEFAULT_TEST_REPLACEMENT_HOSTNAME.length - DEFAULT_TEST_HOSTNAME.length)).toHexString(
            RECORD_LENGTH_SIZE)

        assert(actual.contains("160303" + correctRecordLength + "01" + correctMessageLength + "0303", ignoreCase = true))
    }
}