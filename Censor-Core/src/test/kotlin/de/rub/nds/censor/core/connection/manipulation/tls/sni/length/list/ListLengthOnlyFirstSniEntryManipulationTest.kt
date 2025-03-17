package de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.AdditionalEntryManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.SniTest
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.OverrideHostnameManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_NAME_LENGTH_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_NAME_TYPE_LENGTH
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import org.junit.jupiter.api.Assertions

class ListLengthOnlyFirstSniEntryManipulationTest: SniTest<ListLengthOnlyFirstSniEntryManipulation>(fails = true) {

    override fun extraManipulations(): Collection<TlsManipulation> {
        return  super.extraManipulations() +
                AdditionalEntryManipulation(DEFAULT_TEST_HOSTNAME, 1) +
                OverrideHostnameManipulation(0, DEFAULT_TEST_REPLACEMENT_HOSTNAME) // necessary because else it is already default
    }
    override fun targetManipulations(): Collection<ListLengthOnlyFirstSniEntryManipulation> {
        return listOf(
            ListLengthOnlyFirstSniEntryManipulation()
        )
    }

    override fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: ListLengthOnlyFirstSniEntryManipulation, exception: Exception?) {
        val message = connection.state.workflowTrace.lastReceivingAction.receivedMessages[0]
        if (message !is CoreClientHelloMessage) throw Exception()

        // check all other lengths remain the same after manipulations
        val correctOffset = DEFAULT_TEST_REPLACEMENT_HOSTNAME.length + SNI_NAME_LENGTH_LENGTH + SNI_NAME_TYPE_LENGTH
        Assertions.assertEquals(defaultMessageLength + correctOffset, message.getLength().value)
        Assertions.assertEquals(defaultExtensionsLength + correctOffset, message.getExtensionsLength().value)

        val sni = message.getExtension(ServerNameIndicationExtensionMessage::class.java)
        Assertions.assertEquals(defaultSniExtensionLength + correctOffset, sni.extensionLength.value)

        // correctly modified to new value
        Assertions.assertEquals(DEFAULT_TEST_REPLACEMENT_HOSTNAME.length + SNI_NAME_LENGTH_LENGTH + SNI_NAME_TYPE_LENGTH, sni.serverNameListLength.value)
    }
}