package de.rub.nds.censor.core.connection.manipulation.tls.extension.length

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.constants.ManipulationConstants.GARBAGE_BYTE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_FIELD_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_SIZE
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_TO_OUTER
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSIONS_LENGTH_LENGTH
import de.rub.nds.censor.core.util.Util.toHexString
import org.junit.jupiter.api.Assertions

class ExtensionsLengthTooLongGarbageManipulationTest: SniTest<ExtensionsLengthTooLongGarbageManipulation>(fails = true) {
    override fun targetManipulations(): Collection<ExtensionsLengthTooLongGarbageManipulation> {
        return listOf(
            ExtensionsLengthTooLongGarbageManipulation(0),
            ExtensionsLengthTooLongGarbageManipulation(20)
        )
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ExtensionsLengthTooLongGarbageManipulation, exception: Exception?) {
        val actual = connection.state.workflowTrace.lastReceivingAction.receivedRecords[0].completeRecordBytes.value.toHexString()

        // check if garbage bytes present at end of extensions
        Assertions.assertEquals(actual.substring(actual.length - manipulation.garbageCount * 2), GARBAGE_BYTE.toHexString().repeat(manipulation.garbageCount))

        // check correct modification of all super lengths with garbage count
        val correctOffset = manipulation.garbageCount
        val correctMessageLength = (defaultMessageLength + correctOffset).toHexString(MESSAGE_LENGTH_SIZE)
        val correctExtensionsLength = (defaultExtensionsLength + correctOffset).toHexString(TLS_EXTENSIONS_LENGTH_LENGTH)

        assert(actual.contains((defaultMessageLength + correctOffset + MESSAGE_LENGTH_TO_OUTER).toHexString(MESSAGE_LENGTH_FIELD_LENGTH) + "01" + correctMessageLength + "0303", ignoreCase = true))
        assert(actual.contains("00000100" + correctExtensionsLength + "000b00", ignoreCase = true))
    }
}