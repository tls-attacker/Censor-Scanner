package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.BasicTlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.util.Util.getExtension
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace

/**
 * Overrides the extension bytes of an extension.
 */
class OverrideExtensionTypeManipulation(
    private val tlsExtension: Class<out ExtensionMessage>,
    val extensionType: ByteArray
) : TlsManipulation() {

    init {
        require(extensionType.size == 2) { "Extension type must be 2 bytes long" }
    }

    override fun afterWorkflowTrace(
        workflowTrace: WorkflowTrace, tlsConnection: BasicTlsConnection, config: Config
    ) {
        // create modification
        val incorrectExtensionType = ModifiableByteArray()
        val incorrectExtensionTypeModification = ByteArrayExplicitValueModification()
        incorrectExtensionTypeModification.explicitValue = extensionType
        incorrectExtensionType.modification = incorrectExtensionTypeModification

        // override length
        workflowTrace.getExtension(tlsExtension).extensionType = incorrectExtensionType
    }

    override val name: String
        get() = "override_extension_type(tlsExtension=$tlsExtension, extensionType=$extensionType)"
}