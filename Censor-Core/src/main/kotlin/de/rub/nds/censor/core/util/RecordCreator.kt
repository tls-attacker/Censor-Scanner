package de.rub.nds.censor.core.util

import de.rub.nds.censor.core.connection.BasicTlsConnection
import de.rub.nds.censor.core.constants.RecordManipulationType
import de.rub.nds.modifiablevariable.ModifiableVariableFactory
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.tlsattacker.core.constants.CipherSuite
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.parser.cert.CleanRecordByteSeperator
import de.rub.nds.tlsattacker.core.record.Record
import de.rub.nds.tlsattacker.core.record.cipher.CipherState
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet
import de.rub.nds.tlsattacker.core.record.compressor.RecordCompressor
import de.rub.nds.tlsattacker.core.record.crypto.RecordEncryptor
import de.rub.nds.tlsattacker.core.record.preparator.RecordPreparator
import de.rub.nds.tlsattacker.core.record.serializer.RecordSerializer
import de.rub.nds.tlsattacker.core.state.State
import java.io.ByteArrayInputStream
import kotlin.math.min

/**
 * This class parses a series of TLS messages to TLS records. Contains lots of TLS-Attacker code, so we separate it
 * here.
 */
class RecordCreator {

    // make overridable but set default size
    private val defaultMaxRecordSize = 16384
    var initialMaxRecordSize = defaultMaxRecordSize
    var insertRecordOfTypeBefore: RecordManipulationType? = null
    var insertRecordOfTypeAfter: RecordManipulationType? = null
    var insertRecordOfTypeBetween: RecordManipulationType? = null

    fun tlsMessagesToTlsRecords(
        messages: Collection<ProtocolMessage>,
        tlsConnection: BasicTlsConnection
    ): List<Record> {
        return messages.flatMap { tlsMessageToRecords(it, tlsConnection) }
    }

    private fun tlsMessageToRecords(message: ProtocolMessage, tlsConnection: BasicTlsConnection): List<Record> {
        val state = tlsConnection.state
        var preparator = message.getPreparator(state.context)
        preparator.prepare()

        tlsConnection.betweenMessagePreparationCallback(message)

        preparator = message.getPreparator(state.context)
        preparator.prepare()

        val serializer = message.getSerializer(state.context)
        val serializedMessage = serializer.serialize()
        message.setCompleteResultingMessage(serializedMessage)
        ProtocolMessageUtil.updateDigestForProtocolMessage(message, state.tlsContext)
        if (message.getAdjustContext()) {
            ProtocolMessageUtil.adjustContextForProtocolMessage(message, state.tlsContext)
        }

        tlsConnection.afterMessageSerializationCallback(message, this)

        // parse message bytes into record
        val protocolMessageType = message.protocolMessageType
        val records: MutableList<Record> = mutableListOf()

        // create initial record
        val initialRecordSize = min(initialMaxRecordSize, serializedMessage.size)
        records.add(Record().apply { setCleanProtocolMessageBytes(serializedMessage.copyOf(initialRecordSize)) })

        if (initialRecordSize < serializedMessage.size) {
            // create more records dynamically
            val separator = CleanRecordByteSeperator(
                defaultMaxRecordSize,
                ByteArrayInputStream(serializedMessage.copyOfRange(initialRecordSize, serializedMessage.size)),
                true,
                false
            )
            mutableListOf<Record>().also { tmpRecords ->
                separator.parse(tmpRecords)
                records.addAll(tmpRecords)
            }
        }

        tlsConnection.afterAllRecordsCreationCallback(this, records)

        // prepare and serialize the records
        records.forEachIndexed { index, record ->
            if (index == 0 && insertRecordOfTypeBefore != null) {
                handleTlsRecord(record, insertRecordOfTypeBefore!!.protocolType, state, connection = tlsConnection)
            } else if (index == records.size -1 && insertRecordOfTypeAfter != null) {
                handleTlsRecord(record, insertRecordOfTypeAfter!!.protocolType, state, connection = tlsConnection)
            } else if (index == records.size/2 && insertRecordOfTypeBetween != null) {
                handleTlsRecord(record, insertRecordOfTypeBetween!!.protocolType, state, connection = tlsConnection)
            } else {
                handleTlsRecord(record, protocolMessageType, state, connection = tlsConnection)
            }
        }

        if (message.getAdjustContext()) {
            ProtocolMessageUtil.adjustContextAfterSerializeForProtocolMessage(message, state.tlsContext)
        }

        return records
    }

    private fun handleTlsRecord(record: Record, messageType: ProtocolMessageType, state: State, connection: BasicTlsConnection): Record {

        // set content message type
        record.contentMessageType = messageType
        record.contentType
        // prepare message
        val preparator: RecordPreparator = record.getRecordPreparator(
            state.tlsContext,
            RecordEncryptor(
                RecordNullCipher(
                    state.tlsContext,
                    // placeholder without meaning...
                    CipherState(
                        ProtocolVersion.TLS10,
                        CipherSuite.GREASE_01,
                        KeySet(),
                        true
                    )
                ),
                state.tlsContext
            ),
            RecordCompressor(state.tlsContext),
            messageType
        )
        preparator.prepare()
        preparator.afterPrepare()

        connection.afterRecordsCreationCallback(record)

        // serialize record
        val serializer: RecordSerializer = record.recordSerializer
        val serializedMessage = serializer.serialize()
        record.setCompleteRecordBytes(serializedMessage)
        record.completeRecordBytes.modification = ByteArrayExplicitValueModification(record.completeRecordBytes.value)
        return record
    }
}