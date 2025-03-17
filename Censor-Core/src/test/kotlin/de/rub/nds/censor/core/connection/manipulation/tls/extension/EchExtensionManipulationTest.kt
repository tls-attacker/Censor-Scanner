package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.censor.core.constants.EncryptedClientHelloVersion
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import java.lang.Exception

class EchExtensionManipulationTest: ManipulationTest<EchExtensionManipulation>() {

    override fun targetManipulations(): Collection<EchExtensionManipulation> {
        return listOf(
            EchExtensionManipulation(DEFAULT_TEST_HOSTNAME, EncryptedClientHelloVersion.DRAFT_07, true),
            EchExtensionManipulation(DEFAULT_TEST_HOSTNAME, EncryptedClientHelloVersion.DRAFT_08, true),
            EchExtensionManipulation(DEFAULT_TEST_HOSTNAME, EncryptedClientHelloVersion.DRAFT_09, true),
            EchExtensionManipulation(DEFAULT_TEST_HOSTNAME, EncryptedClientHelloVersion.DRAFT_10, true),
            EchExtensionManipulation(DEFAULT_TEST_HOSTNAME, EncryptedClientHelloVersion.DRAFT_11, true),
            EchExtensionManipulation(DEFAULT_TEST_HOSTNAME, EncryptedClientHelloVersion.DRAFT_12, true),
            EchExtensionManipulation(DEFAULT_TEST_HOSTNAME, EncryptedClientHelloVersion.DRAFT_13_14_15_16_17, true),
            EchExtensionManipulation(DEFAULT_TEST_HOSTNAME, EncryptedClientHelloVersion.DRAFT_12, false),
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: EchExtensionManipulation, exception: Exception?) {
        val expected = manipulation.echVersion
        if (manipulation.enable) {
            assert(
                connection.state.workflowTrace.lastReceivingAction.receivedMessages
                    .filterIsInstance(ClientHelloMessage::class.java)[0].extensions.any {
                    it.extensionType.value.contentEquals(
                        expected.versionBytes
                    )
                }
            )
        } else {
            assert(
                connection.state.workflowTrace.lastReceivingAction.receivedMessages
                    .filterIsInstance(ClientHelloMessage::class.java)[0].extensions.none {
                    it.extensionType.value.contentEquals(
                        expected.versionBytes
                    )
                }
            )
        }
    }
}