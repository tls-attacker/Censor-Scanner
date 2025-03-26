package de.rub.nds.censor.core.connection.manipulation.tls

import de.rub.nds.censor.core.connection.BasicTlsConnection
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace
import de.rub.nds.tlsattacker.core.workflow.action.WaitAction

/**
 * Waits the specified amount of time after sending the first message flight.
 */
class WaitManipulation(private val waitTime: Long = 1000): TlsManipulation() {
    override fun afterWorkflowTrace(workflowTrace: WorkflowTrace, tlsConnection: BasicTlsConnection, config: Config) {
        workflowTrace.tlsActions.add(1, WaitAction(waitTime))
    }

    override val name: String
        get() = "WaitManipulation(waitTime=$waitTime)"
}