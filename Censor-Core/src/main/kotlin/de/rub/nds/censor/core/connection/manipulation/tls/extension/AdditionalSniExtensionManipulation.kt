package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_NAME_LENGTH_LENGTH
import de.rub.nds.censor.core.constants.ManipulationConstants.SNI_NAME_TYPE_LENGTH
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.util.Util.getExtensions
import de.rub.nds.censor.core.util.Util.toHexString
import de.rub.nds.modifiablevariable.ModifiableVariableFactory
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.constants.ExtensionType
import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage
import de.rub.nds.tlsattacker.core.state.State

/**
 * Adds an SNI extension to the connection at the specified place. Use -x for indexing from behind, where -1 is equal
 * to the last index.
 */
class AdditionalSniExtensionManipulation(val place: Int, val hostname: String): TlsManipulation() {

    override val name: String
        get() = "additional_sni(place=$place, hostname=$hostname)"

    @OptIn(ExperimentalStdlibApi::class)
    override fun afterStateGeneration(state: State) {
        val extensions = state.workflowTrace.getExtensions()

        // determine index
        val index = if (place < 0) {
            place + extensions.size
        } else {
            place
        }
        if(index > extensions.size || index < 0) {
            throw NotConnectableException(ConnectionReturn.INTERNAL_ERROR, "Can not add SNI extension at index $place as only ${extensions.size} messages exist")
        }

        // create ServerNameIndication with given hostname, use unknown message to not break SNI detection in util
        val message = UnknownExtensionMessage()
        val nameLength = hostname.length
        val listLength = nameLength + SNI_NAME_LENGTH_LENGTH + SNI_NAME_TYPE_LENGTH
        val extensionContent =
            listLength.toHexString(2).hexToByteArray() +
            "00".hexToByteArray() +
            // name length
            nameLength.toHexString(2).hexToByteArray() +
            // name
            hostname.toByteArray()
        val contentModification = ByteArrayExplicitValueModification(extensionContent)
        val extensionTypeModification = ByteArrayExplicitValueModification(ExtensionType.SERVER_NAME_INDICATION.value)
        val extensionLengthModification = IntegerExplicitValueModification(extensionContent.size)
        message.extensionContent = ModifiableVariableFactory.safelySetValue(message.extensionContent, extensionContent)
        message.extensionContent.modification = contentModification
        message.extensionType = ModifiableVariableFactory.safelySetValue(message.extensionType, ExtensionType.SERVER_NAME_INDICATION.value)
        message.extensionType.modification = extensionTypeModification
        message.extensionLength = ModifiableVariableFactory.safelySetValue(message.extensionLength, extensionContent.size)
        message.extensionLength.modification = extensionLengthModification
        extensions.add(index, message)
    }
}