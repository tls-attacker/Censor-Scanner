/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.MESSAGE_LENGTH_TO_OUTER
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_EXTENSION_HEADER
import de.rub.nds.censor.core.constants.RecordManipulationType
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.util.RecordCreator
import de.rub.nds.censor.core.util.Util.applyManipulationType
import de.rub.nds.censor.core.util.Util.getParsedExtensionsUntilFirstSni
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import de.rub.nds.tlsattacker.core.record.Record

/**
 * Applied record fragmentation at the given RecordFragmentationPoint
 */
class RecordFragmentationManipulation(val recordFragmentationPoint: RecordFragmentationPoint, val protocolMessageTypeToInject: RecordManipulationType? = null) : TlsManipulation() {

    // add record and set type
    override fun afterAllRecordsCreation(recordCreator: RecordCreator, records: MutableList<Record>) {
        if (protocolMessageTypeToInject != null) {
            var injectPosition = records.size/2
            if (recordCreator.insertRecordOfTypeBefore != null && recordCreator.insertRecordOfTypeAfter == null) { // only record inserted before
                injectPosition += 1
            }
            recordCreator.insertRecordOfTypeBetween = protocolMessageTypeToInject
            val recordToAdd = Record().apply { applyManipulationType(protocolMessageTypeToInject) }
            records.add(injectPosition, recordToAdd)
        }
    }

    // We need to apply record fragmentation after serialization because only then other manipulations are applied for setting correct size
    override fun afterMessageSerialization(message: ProtocolMessage, tlsConfig: Config, recordCreator: RecordCreator) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only add record fragmentation with explicit points in ClientHello messages, skipping")
            return
        }
        val sni = message.getExtension(ServerNameIndicationExtensionMessage::class.java)
            ?: // removed with other strategy
            if (recordFragmentationPoint == RecordFragmentationPoint.BEFORE_SNI) {
                recordCreator.initialMaxRecordSize = 20 // fragment somewhere hardcoded once
                return
            } else {
                throw NotConnectableException(ConnectionReturn.INAPPLICABLE, "Tried to apply record fragmentation at specific point without SNI being present!")
            }
        // we need original values in this line because of other manipulations in message or extensions length --> this will break
        val lengthUntilSni = try {
            message.length.originalValue + MESSAGE_LENGTH_TO_OUTER - message.extensionsLength.originalValue + message.getParsedExtensionsUntilFirstSni()
        } catch (e: IllegalArgumentException) {
            // no sni present
            throw NotConnectableException(ConnectionReturn.INAPPLICABLE, "No SNI present")
        }

        val recordSize: Int = try {
            when (recordFragmentationPoint) {
                RecordFragmentationPoint.IN_MESSAGE_HEADER -> 2
                RecordFragmentationPoint.BEFORE_SNI -> lengthUntilSni
                RecordFragmentationPoint.IN_HOSTNAME -> lengthUntilSni + (sni.serverNameList[0].serverName.value.size/2) + SNI_FIRST_HOSTNAME_TO_EXTENSION_LENGTH + TLS_EXTENSION_HEADER
                RecordFragmentationPoint.AFTER_SNI -> lengthUntilSni + sni.extensionLength.value + TLS_EXTENSION_HEADER
            }
        } catch (e: IndexOutOfBoundsException) {
            throw NotConnectableException(ConnectionReturn.INAPPLICABLE, "No entry in SNI because of other manipulations")
        }
        recordCreator.initialMaxRecordSize = recordSize
    }

    override val name: String
        get() = "record_fragmentation(recordFragmentationPoint=$recordFragmentationPoint, protocolMessageTypeToInject=$protocolMessageTypeToInject)"
}