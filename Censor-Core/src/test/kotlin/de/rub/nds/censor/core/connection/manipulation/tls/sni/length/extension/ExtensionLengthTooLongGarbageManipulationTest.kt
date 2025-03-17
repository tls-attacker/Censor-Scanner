package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.extension

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants.GARBAGE_BYTE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_FIELD_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_TO_OUTER
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSIONS_LENGTH_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSION_LENGTH_LENGTH
import de.rub.nds.censor.core.util.Util.toHexString

class ExtensionLengthTooLongGarbageManipulationTest: SniTest<ExtensionLengthTooLongGarbageManipulation>(fails = true) {
    override fun targetManipulations(): Collection<ExtensionLengthTooLongGarbageManipulation> {
        return listOf(
            ExtensionLengthTooLongGarbageManipulation(0),
            ExtensionLengthTooLongGarbageManipulation(20)
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ExtensionLengthTooLongGarbageManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // check if garbage bytes present at end of extension
        assert(actual.contains(DEFAULT_TEST_HOSTNAME.toByteArray().toHexString() + GARBAGE_BYTE.toHexString().repeat(manipulation.garbageCount)))

        // check correct modification of all super lengths with garbage count
        val correctOffset = manipulation.garbageCount
        val correctMessageLength = (defaultMessageLength + correctOffset).toHexString(MESSAGE_LENGTH_SIZE)
        val correctExtensionsLength = (defaultExtensionsLength + correctOffset).toHexString(TLS_EXTENSIONS_LENGTH_LENGTH)
        val correctExtensionLength = (defaultSniExtensionLength + correctOffset).toHexString(TLS_EXTENSION_LENGTH_LENGTH)

        assert(actual.contains((defaultMessageLength + correctOffset + MESSAGE_LENGTH_TO_OUTER).toHexString(MESSAGE_LENGTH_FIELD_LENGTH) + "01" + correctMessageLength + "0303", ignoreCase = true))
        assert(actual.contains("00000100" + correctExtensionsLength + "000b00", ignoreCase = true))
        assert(actual.contains("01040000" + correctExtensionLength + "000e0000", ignoreCase = true))
    }
}