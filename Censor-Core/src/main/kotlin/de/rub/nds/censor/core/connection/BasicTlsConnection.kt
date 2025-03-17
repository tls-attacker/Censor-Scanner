/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2023
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.exception.PcapException
import de.rub.nds.censor.core.network.ConnectionTuple
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.core.util.RecordCreator
import de.rub.nds.censor.core.util.Util.containsHostname
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.connection.OutboundConnection
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType
import de.rub.nds.tlsattacker.core.constants.RunningModeType
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedClientHelloMessage
import de.rub.nds.tlsattacker.core.record.Record
import de.rub.nds.tlsattacker.core.state.State
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceResultUtil
import de.rub.nds.tlsattacker.core.workflow.action.MessageActionFactory
import de.rub.nds.tlsattacker.core.workflow.action.SendAction
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType
import de.rub.nds.tlsattacker.transport.ConnectionEndType
import de.rub.nds.x509attacker.x509.model.X509Certificate
import java.util.*

/**
 * Base class for [TlsConnection], [DtlsConnection], and further subtypes of
 * TLSConnections. Combinations of [TlsManipulation]s can be specified on a basic tls connection.
 * Contains information about sent and received message as well.
 */
sealed class BasicTlsConnection(
    ip: IpAddress,
    serverPort: Int,
    timeout: Int,
    private var censorScanType: CensorScanType,
    clientPort: Int = -1,
    pcapCapturer: PcapCapturer? = null,
    private val keyLogFilePath: String = "",
    private val hostname: String? = null,
    private val simpleScanAnswerBytes: ByteArray = byteArrayOf(65, 65, 65, 65, 65)
) : TcpConnection<TlsManipulation>(ip, serverPort, timeout, clientPort, pcapCapturer) {

    // lateinit as all are instantiated during the connection buildup
    protected lateinit var tlsConfig: Config
    lateinit var state: State
    protected lateinit var executor: WorkflowExecutor
    protected lateinit var workflowTrace: WorkflowTrace

    private lateinit var receivedMessages: List<ProtocolMessage>
    private lateinit var sentMessages: List<ProtocolMessage>

    abstract val identifier: String

    override val name: String
        get() = super.name + identifier

    /** Generates a config usable in a TLS connection.  */
    protected open fun generateConfig(): Config {
        val tlsConfig = Config()
        // no sni on default
        tlsConfig.isAddServerNameIndicationExtension = false
        tlsConfig.isFinishWithCloseNotify = false
        tlsConfig.isWorkflowExecutorShouldOpen = false
        tlsConfig.isWorkflowExecutorShouldClose = (censorScanType != CensorScanType.SIMPLE)
        tlsConfig.isResetClientSourcePort = false
        tlsConfig.isRetryFailedClientTcpSocketInitialization = true
        tlsConfig.isStealthMode = true
        if (this.keyLogFilePath != "") {
            tlsConfig.keylogFilePath = keyLogFilePath
            tlsConfig.isWriteKeylogFile = true
        }
        return tlsConfig
    }

    /** Generates an OutboundConnection for the TLSConnection.  */
    protected open fun generateOutboundConnection(): OutboundConnection {
        val outboundConnection = OutboundConnection()
        outboundConnection.connectionTimeout = timeout
        outboundConnection.timeout = timeout
        outboundConnection.ip = ip.address
        outboundConnection.port = serverPort
        if (clientPort != -1) {
            logger.debug("Setting client port manually.")
            outboundConnection.sourcePort = clientPort
        } else {
            logger.debug("Setting client port automatically")
        }
        return outboundConnection
    }

    /**
     * Extracts the [ConnectionTuple] from the prepared connection.
     */
    protected abstract fun extractConnectionTuple(state: State): ConnectionTuple

    /** Subclasses might set their own WorkflowExecutor type  */
    protected abstract fun setWorkflowExecutor(state: State): WorkflowExecutor

    /**
     * Initializes the underlying socket and Config before attempting the TLS connection. Needed for
     * extracting the client port from the TCP connection before sending TLS messages and for
     * providing callback functions.
     */
    open fun initializeConnectionParameters() {
        logger.debug("Preparing $name")
        tlsConfig = generateConfig()

        afterConfigInitCallbacks(tlsConfig)

        // set connection values
        val outboundConnection = generateOutboundConnection()
        afterConnectionPrepareCallbacks(outboundConnection)

        tlsConfig.defaultClientConnection = outboundConnection

        workflowTrace = generateWorkflowTrace()
        afterWorkflowTraceCallbacks(workflowTrace)

        state = generateState(tlsConfig, workflowTrace)
        afterStateGenerationCallback(state)
        executor = setWorkflowExecutor(state)
    }

    open fun generateState(tlsConfig: Config, workflowTrace: WorkflowTrace): State {
        return State(tlsConfig, workflowTrace)
    }

    /**
     * Prepares the underlying socket for connecting to the server. Provides the timeout from Censor-Scanner to
     * TLS-Attacker from the config.
     */
    @Throws(NotConnectableException::class)
    abstract fun createAndBindSocket(executor: WorkflowExecutor, state: State)

    /**
     * Subclasses connect the socket over the network here.
     */
    @Throws(NotConnectableException::class)
    abstract fun connectSocket(state: State)

    /**
     * Converts [ProtocolMessage]s to Records. This way, we can injector alter records from Censor-Scanner.
     */
    private fun convertMessagesToRecords(workflowTrace: WorkflowTrace) {
        val action = workflowTrace.messageActions.filterIsInstance<SendAction>().getOrNull(0)

        if (action == null || action.configuredMessages.filterIsInstance<CoreClientHelloMessage>().isEmpty()) {
            throw NotConnectableException(
                ConnectionReturn.INTERNAL_ERROR,
                "Could not find TLS Client Hello message in first SendAction"
            )
        }

        // replace tls messages with records
        action.also { messageAction ->
            if (messageAction.configuredRecords == null) {
                messageAction.configuredRecords = mutableListOf()
            }
            messageAction.configuredRecords.clear()
            messageAction.configuredRecords.addAll(
                RecordCreator()
                    .also { afterRecordCreatorInitCallbacks(it) }
                    .tlsMessagesToTlsRecords(messageAction.configuredMessages, this))
            messageAction.configuredMessages = null
        }
    }

    /**
     * Executes the connection prepared earlier. The connection must be prepared and the socket
     * initialized before calling this method. Alternatively, use isConnectable for this class to
     * handle the initialization for you.
     *
     * @return True, if the server finishes the handshake.
     */
    @Throws(NotConnectableException::class)
    protected open fun finalizeConnectionAttempt(state: State) {
        try {
            executor.executeWorkflow()
        } catch (e: Exception) {
            // should not occur even in censored connections
            throw NotConnectableException(ConnectionReturn.INTERNAL_ERROR, e)
        }
        receivedMessages = WorkflowTraceResultUtil.getAllReceivedMessages(state.workflowTrace)
        sentMessages = WorkflowTraceResultUtil.getAllSentMessages(state.workflowTrace)

        // evaluate whether the connection executed as planned
        val working = when (censorScanType) {
            CensorScanType.DIRECT -> workflowTrace.executedAsPlanned()

            CensorScanType.ECHO -> {
                WorkflowTraceResultUtil.didReceiveMessage(
                    state.workflowTrace, HandshakeMessageType.CLIENT_HELLO
                )
            }

            CensorScanType.SIMPLE -> {
                try {
                    state.context.transportHandler.fetchData()
                        .contentEquals(simpleScanAnswerBytes) // fixed bytes from own controlled server in Germany
                } catch (e: Exception) {
                    logger.warn("Could not receive data in simple connection due to $e")
                    false
                } finally {
                    state.context.transportHandler.closeConnection()
                }
            }
        }

        if (!working && state.context.tlsContext.isReceivedFatalAlert) {
            throw NotConnectableException(ConnectionReturn.TLS_ALERT)
        }

        // check for matching certificate if hostname set
        val certificate = if (censorScanType == CensorScanType.DIRECT && hostname != null) {
            val cert: X509Certificate? = state.tlsContext.serverCertificateChain?.getCertificate(0)
            if (cert == null) {
                ConnectionReturn.NO_CERTIFICATE
            } else {
                val certCorrect = cert.containsHostname(hostname, logger)
                if (certCorrect) {
                    ConnectionReturn.WORKING
                } else {
                    ConnectionReturn.WRONG_CERTIFICATE
                }
            }
        } else {
            ConnectionReturn.WORKING
        }

        // go over all combination possibilities of working and certificate
        if (working && certificate == ConnectionReturn.NO_CERTIFICATE) {
            throw NotConnectableException(ConnectionReturn.NO_CERTIFICATE_BUT_WORKING)
        } else if (!working && certificate == ConnectionReturn.NO_CERTIFICATE) {
            throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER)
        } else if (working && certificate == ConnectionReturn.WRONG_CERTIFICATE) {
            throw NotConnectableException(ConnectionReturn.WRONG_CERTIFICATE_BUT_WORKING)
        } else if (!working && certificate == ConnectionReturn.WRONG_CERTIFICATE) {
            throw NotConnectableException(ConnectionReturn.WRONG_CERTIFICATE)
        } else if (!working) {
            // correct certificate
            throw NotConnectableException(ConnectionReturn.ANALYZE_FURTHER)
        }
    }

    /**
     * Opens and closes a TLS connection to the server. Retries until the specified timeout is
     * reached.
     *
     * @return Whether the server is reachable
     */
    @Throws(NotConnectableException::class)
    override suspend fun connect() {
        var connectionTuple: ConnectionTuple? = null
        try {
            logger.debug("Initializing socket values in TLS-Attacker for $ip")
            initializeConnectionParameters()
            logger.debug("Creating and binding socket $ip")
            createAndBindSocket(executor, state)
            connectionTuple = extractConnectionTuple(state)
            // update client port
            clientPort = connectionTuple.port1
            // only start when past results for our connection (port reusage) have been analyzed
            while(true) {
                try {
                    pcapCapturer?.register(connectionTuple)
                } catch (e: PcapException) {
                    Thread.sleep(200)
                    continue
                }
                logger.debug("Registered PcapCapturer for $connectionTuple")
                break
            }
            logger.debug("Connecting socket for $ip")
            connectSocket(state)
            // allow for callbacks in manipulations
            afterTransportHandlerInitCallbacks(state)
            logger.debug("Converting TLS messages to TLS records for $ip")
            convertMessagesToRecords(workflowTrace)
            logger.debug("Executing connection on connected socket for $ip")
            finalizeConnectionAttempt(state)
        } catch (e: NotConnectableException) {
            // keep blocking
            Thread.sleep(1000)
            // further analyze why we could not connect and throw the more detailed exception
            try {
                analyzeCancelledConnection(connectionTuple, e, false, pcapCapturer)
                    .also { logger.debug(it) }
                    .also { throw it }
            } catch (e: NotConnectableException) {
                if (e.reason == ConnectionReturn.UNKNOWN) {
                    logger.debug("Unknown analysis - waiting additional 5 seconds for more packets to arrive")
                    // keep blocking
                    Thread.sleep(5000)
                    analyzeCancelledConnection(connectionTuple, e, true, pcapCapturer)
                        .also { logger.debug(it) }
                        .also { throw it }
                } else {
                    throw e
                }
            }
        } catch (e: Exception) {
            logger.error("Internal error in connection attempt to $this with exception: ", e)
            throw NotConnectableException(ConnectionReturn.INTERNAL_ERROR)
        } finally {
            connectionTuple?.also { tuple -> pcapCapturer?.deregister(tuple) }
        }
    }

    /**
     * Generates a [WorkflowTrace] for ECHO scans.
     */
    private fun generateEchoWorkflowTrace(): WorkflowTrace {
        val workflowTrace = WorkflowTrace()
        workflowTrace.addTlsAction(
            MessageActionFactory.createTLSAction(
                tlsConfig,
                tlsConfig.defaultClientConnection,
                ConnectionEndType.CLIENT,
                ClientHelloMessage(tlsConfig)
            )
        )
        workflowTrace.addTlsAction(
            MessageActionFactory.createTLSAction(
                tlsConfig,
                tlsConfig.defaultClientConnection,
                ConnectionEndType.SERVER,
                ClientHelloMessage(tlsConfig)
            )
        )
        return workflowTrace
    }

    /**
     * Generates a [WorkflowTrace] for SIMPLE scans.
     */
    private fun generateSimpleWorkflowTrace(): WorkflowTrace {
        val workflowTrace = WorkflowTrace()
        workflowTrace.addTlsAction(
            MessageActionFactory.createTLSAction(
                tlsConfig,
                tlsConfig.defaultClientConnection,
                ConnectionEndType.CLIENT,
                if (tlsConfig.isAddEncryptedClientHelloExtension) EncryptedClientHelloMessage(tlsConfig) else ClientHelloMessage(tlsConfig)
            )
        )
        return workflowTrace
    }

    /**
     * Generates a [WorkflowTrace] for complete TLS handshakes.
     */
    open fun generateDirectWorkflowTrace(tlsConfig: Config): WorkflowTrace {
        return WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(
                WorkflowTraceType.DYNAMIC_HANDSHAKE, RunningModeType.CLIENT
            )
    }

    /**
     * Generates a [WorkflowTrace] for this connection in TLS-Attacker.
     */
    protected fun generateWorkflowTrace(): WorkflowTrace {
        return when (censorScanType) {
            CensorScanType.DIRECT -> generateDirectWorkflowTrace(tlsConfig)
            CensorScanType.ECHO -> generateEchoWorkflowTrace()
            CensorScanType.SIMPLE -> generateSimpleWorkflowTrace()
        }
    }

    private fun afterConnectionPrepareCallbacks(outboundConnection: OutboundConnection) {
        for (manipulation in manipulations) {
            manipulation.afterConnectionPrepare(outboundConnection)
        }
    }

    private fun afterTransportHandlerInitCallbacks(state: State) {
        manipulations.forEach { it.afterTransportHandlerInit(state) }
    }

    protected fun afterConfigInitCallbacks(tlsConfig: Config) {
        manipulations.forEach { it.afterConfigInit(tlsConfig) }
    }

    private fun afterRecordCreatorInitCallbacks(recordCreator: RecordCreator) {
        manipulations.forEach { it.afterRecordCreatorInit(recordCreator) }
    }

    fun betweenMessagePreparationCallback(message: ProtocolMessage) {
        manipulations.forEach { it.betweenMessagePreparation(message, tlsConfig) }
    }

    fun afterMessageSerializationCallback(message: ProtocolMessage, recordCreator: RecordCreator) {
        manipulations.forEach { it.afterMessageSerialization(message, tlsConfig, recordCreator) }
    }

    fun afterRecordsCreationCallback(record: Record) {
        manipulations.forEach { it.afterRecordCreation(record) }
    }

    fun afterAllRecordsCreationCallback(recordCreator: RecordCreator, records: MutableList<Record>) {
        manipulations.forEach { it.afterAllRecordsCreation(recordCreator, records) }
    }

    protected fun afterWorkflowTraceCallbacks(workflowTrace: WorkflowTrace) {
        manipulations.forEach { it.afterWorkflowTrace(workflowTrace, this, tlsConfig) }
    }

    protected fun afterStateGenerationCallback(state: State?) {
        if (state == null) {
            logger.error("State is null, ignoring callback")
            return
        }
        manipulations.forEach { it.afterStateGeneration(state) }
    }
}