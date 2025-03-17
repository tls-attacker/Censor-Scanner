/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tls

import de.rub.nds.censor.core.connection.BasicTlsConnection
import de.rub.nds.censor.core.connection.manipulation.Manipulation
import de.rub.nds.censor.core.util.RecordCreator
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.connection.OutboundConnection
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.record.Record
import de.rub.nds.tlsattacker.core.state.State
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace
import org.apache.logging.log4j.kotlin.Logging

/**
 * Models a censorship circumvention technique. Provides callbacks for the [BasicTlsConnection] it can be registered on.
 */
abstract class TlsManipulation : Manipulation() {

    /**
     * Callback for the connection object.
     */
    open fun afterConnectionPrepare(outboundConnection: OutboundConnection?) {}

    /**
     * Callback for the WorkflowTrace object
     */
    open fun afterWorkflowTrace(workflowTrace: WorkflowTrace, tlsConnection: BasicTlsConnection, config: Config) {}

    /**
     * Callback for state object after it has been initialized from the [WorkflowTrace]
     */
    open fun afterStateGeneration(state: State) {}

    /**
     * Callback for the state object after TransportHandler initialization.
     */
    open fun afterTransportHandlerInit(state: State) {}

    /**
     * Callback for the Config object
     */
    open fun afterConfigInit(tlsConfig: Config) {}

    /**
     * Callback for the RecordCreator object
     */
    open fun afterRecordCreatorInit(recordCreator: RecordCreator) {}

    /**
     * Callback after message serialization
     */
    open fun afterMessageSerialization(message: ProtocolMessage, tlsConfig: Config, recordCreator: RecordCreator) {}

    /**
     * Callback after message preparation
     */
    open fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {}

    /**
     * Callback after record creation is done
     */
    open fun afterRecordCreation(record: Record) {}

    /**
     * Callback after all records are created
     */
    open fun afterAllRecordsCreation(recordCreator: RecordCreator, records: MutableList<Record>) {}

    companion object : Logging

}