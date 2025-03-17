package de.rub.nds.censor.core.connection

import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.connection.OutboundConnection
import de.rub.nds.tlsattacker.core.constants.RunningModeType
import de.rub.nds.tlsattacker.core.http.HttpResponseMessage
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration
import de.rub.nds.tlsattacker.core.state.State
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveTillHttpContentAction
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType

class HttpsConnection(
    ip: IpAddress,
    serverPort: Int,
    timeout: Int,
    censorScanType: CensorScanType,
    val hostname: String,
    clientPort: Int = -1,
    pcapCapturer: PcapCapturer? = null,
    keyLogFilePath: String = ""
) : TlsConnection(ip, serverPort, timeout, censorScanType, clientPort, pcapCapturer, keyLogFilePath, hostname) {

    var firstHttpResponse: HttpResponseMessage? = null

    override fun generateConfig(): Config {
        val config = super.generateConfig()
        config.defaultHttpsRequestPath = "/"
        config.defaultLayerConfiguration = StackConfiguration.HTTPS
        config.workflowTraceType = WorkflowTraceType.DYNAMIC_HTTPS
        return config
    }

    override fun generateOutboundConnection(): OutboundConnection {
        val outboundConnection = super.generateOutboundConnection()
        outboundConnection.hostname = hostname
        return outboundConnection
    }

    override fun generateDirectWorkflowTrace(tlsConfig: Config): WorkflowTrace {
        return WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HTTPS, RunningModeType.CLIENT)
    }

    override fun generateState(tlsConfig: Config, workflowTrace: WorkflowTrace): State {
        val state = super.generateState(tlsConfig, workflowTrace)

        // replace last receiveAction with a ReceiveTillHttpContentAction
        state.workflowTrace
            .removeTlsAction(state.workflowTrace.tlsActions.size - 1)
        state.workflowTrace
            // TODO: do not hardcode defaultConnection here
            .addTlsAction(ReceiveTillHttpContentAction("defaultConnection", "</title>"))

        return state
    }

    override fun finalizeConnectionAttempt(state: State) {
        try {
            super.finalizeConnectionAttempt(state)
        } catch (e: NotConnectableException) {
            if (e.reason.working()) {
                firstHttpResponse = getFirstReceivedHttpMessage(state)
            }
            throw e
        }
        firstHttpResponse = getFirstReceivedHttpMessage(state)
    }

    private fun getFirstReceivedHttpMessage(state: State): HttpResponseMessage? {
        state.workflowTrace.receivingActions.forEach {
            val httpMessages = it.receivedHttpMessages
            if (httpMessages != null && httpMessages.isNotEmpty()) {
                val firstServerAnswer: HttpResponseMessage = try {
                    httpMessages[0] as HttpResponseMessage
                } catch (e: ClassCastException) {
                    logger.warn("Server returned a HttpRequestMessage")
                    return null
                }
                // do not return if nothing received
                if (firstServerAnswer.responseStatusCode != null) {
                    return firstServerAnswer
                }
            }
        }
        return null
    }

    override val identifier: String
        /** Returns information about the manipulations registered on this connection  */
        get() = (listOf("HTTPS") + manipulations.map { it.name }).joinToString(":")
}