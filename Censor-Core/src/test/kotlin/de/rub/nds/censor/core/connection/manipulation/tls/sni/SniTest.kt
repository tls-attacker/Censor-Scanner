package de.rub.nds.censor.core.connection.manipulation.tls.sni

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.ManipulationTest
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil

abstract class SniTest<Manipulation : TlsManipulation>(fails: Boolean = false) : ManipulationTest<Manipulation>(fails) {

    override fun extraManipulations(): Collection<TlsManipulation> {
        return listOf(SniExtensionManipulation(DEFAULT_TEST_HOSTNAME, true))
    }

    protected fun TlsConnection.getSni(): ServerNameIndicationExtensionMessage {
        return WorkflowTraceResultUtil
            .getAllReceivedMessages(state.workflowTrace)
            .filterIsInstance<CoreClientHelloMessage>()[0]
            .extensions.filterIsInstance<ServerNameIndicationExtensionMessage>()[0]
    }

    protected fun TlsConnection.getFirstEntry(): ByteArray {
        return getSni().serverNameList[0].serverName.value
    }

    fun String.fromHexString(): ByteArray {
        check(length % 2 == 0) { "Must have an even length" }

        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }

    fun ByteArray.toHexString() = joinToString("") { "%02x".format(it) }

}