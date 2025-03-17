package de.rub.nds.censor.core.connection.manipulation.tls.extension.length

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.OverrideHostnameManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.HANDSHAKE_TYPE_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.RECORD_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSIONS_LENGTH_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSION_HEADER
import de.rub.nds.censor.core.util.Util.toHexString

class ExtensionsLengthOnlyDefaultFirstSniEntryManipulationTest: SniTest<ExtensionsLengthOnlyDefaultFirstSniEntryManipulation>(fails = true) {
    override fun extraManipulations(): Collection<TlsManipulation> {
        return super.extraManipulations() +
                OverrideHostnameManipulation(0, DEFAULT_TEST_REPLACEMENT_HOSTNAME) // necessary because else it is already default
    }
    override fun targetManipulations(): Collection<ExtensionsLengthOnlyDefaultFirstSniEntryManipulation> {
        return listOf(
            ExtensionsLengthOnlyDefaultFirstSniEntryManipulation(DEFAULT_TEST_HOSTNAME)
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ExtensionsLengthOnlyDefaultFirstSniEntryManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // check correct modification and all super lengths remain the same after manipulations
        val correctOffset = DEFAULT_TEST_REPLACEMENT_HOSTNAME.length - DEFAULT_TEST_HOSTNAME.length
        val correctMessageLength = (defaultMessageLength + correctOffset).toHexString(MESSAGE_LENGTH_SIZE)
        val correctRecordLength = (defaultMessageLength + correctOffset + MESSAGE_LENGTH_SIZE + HANDSHAKE_TYPE_SIZE).toHexString(
            RECORD_LENGTH_SIZE)
        val correctExtensionsLength = (defaultEcPointFormatsExtensionLength + defaultSupportedGroupsExtensionLength + 2 * TLS_EXTENSION_HEADER +
                DEFAULT_TEST_HOSTNAME.length + SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH).toHexString(TLS_EXTENSIONS_LENGTH_LENGTH)

        assert(actual.contains("160303" + correctRecordLength + "01" + correctMessageLength + "0303", ignoreCase = true))
        assert(actual.contains("00000100" + correctExtensionsLength + "000b00", ignoreCase = true))
    }
}