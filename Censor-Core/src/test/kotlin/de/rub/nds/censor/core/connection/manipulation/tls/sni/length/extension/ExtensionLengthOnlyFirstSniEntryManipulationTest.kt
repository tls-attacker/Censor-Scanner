package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.extension

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.AdditionalEntryManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.OverrideHostnameManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.HANDSHAKE_TYPE_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.RECORD_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_LIST_LENGTH_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_NAME_LENGTH_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_NAME_TYPE_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSIONS_LENGTH_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSION_LENGTH_LENGTH
import de.rub.nds.censor.core.util.Util.toHexString

class ExtensionLengthOnlyFirstSniEntryManipulationTest: SniTest<ExtensionLengthOnlyFirstSniEntryManipulation>(fails = true) {
    override fun extraManipulations(): Collection<TlsManipulation> {
        return  super.extraManipulations() +
                AdditionalEntryManipulation(DEFAULT_TEST_HOSTNAME, 1) +
                OverrideHostnameManipulation(0, DEFAULT_TEST_REPLACEMENT_HOSTNAME) // necessary because else it is already default
    }
    override fun targetManipulations(): Collection<ExtensionLengthOnlyFirstSniEntryManipulation> {
        return listOf(
            ExtensionLengthOnlyFirstSniEntryManipulation()
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ExtensionLengthOnlyFirstSniEntryManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // check correct modification and all super lengths remain the same after manipulations
        val correctOffset = DEFAULT_TEST_REPLACEMENT_HOSTNAME.length + SNI_NAME_LENGTH_LENGTH + SNI_NAME_TYPE_LENGTH
        val correctMessageLength = (defaultMessageLength + correctOffset).toHexString(MESSAGE_LENGTH_SIZE)
        val correctRecordLength = (defaultMessageLength + correctOffset + MESSAGE_LENGTH_SIZE + HANDSHAKE_TYPE_SIZE).toHexString(
            RECORD_LENGTH_SIZE
        )
        val correctExtensionsLength = (defaultExtensionsLength + correctOffset).toHexString(TLS_EXTENSIONS_LENGTH_LENGTH)
        val correctExtensionLength = (DEFAULT_TEST_REPLACEMENT_HOSTNAME.length + SNI_NAME_LENGTH_LENGTH + SNI_NAME_TYPE_LENGTH + SNI_LIST_LENGTH_LENGTH).toHexString(TLS_EXTENSION_LENGTH_LENGTH)

        assert(actual.contains("160303" + correctRecordLength + "01" + correctMessageLength + "0303", ignoreCase = true))
        assert(actual.contains("00000100" + correctExtensionsLength + "000b00", ignoreCase = true))
        assert(actual.contains("01040000" + correctExtensionLength + "00220000", ignoreCase = true))
    }
}