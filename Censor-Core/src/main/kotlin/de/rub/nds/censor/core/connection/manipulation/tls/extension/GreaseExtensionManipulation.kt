/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tls.extension

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.GreaseType
import de.rub.nds.censor.core.util.Util.getExtension
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.message.extension.HeartbeatExtensionMessage
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace

/**
 * Adds a GREASE extension to the TLS connection
 * TODO: test or remove
 */
class GreaseExtensionManipulation(private val enable: Boolean, private val greaseType: GreaseType) : TlsManipulation() {
    override fun afterConfigInit(tlsConfig: Config) {
        // add heartbeat extension and change to Grease extension later
        tlsConfig.isAddHeartbeatExtension = enable
    }

    override fun afterWorkflowTrace(
        workflowTrace: WorkflowTrace,
        tlsConnection: de.rub.nds.censor.core.connection.BasicTlsConnection,
        config: Config
    ) {
        // override extension bytes of heartbeat extension
        val incorrectExtensionType = ModifiableByteArray()
        val incorrectExtensionTypeModification = ByteArrayExplicitValueModification()
        incorrectExtensionTypeModification.explicitValue = greaseType.extensionBytes
        workflowTrace.getExtension(HeartbeatExtensionMessage::class.java).extensionType = incorrectExtensionType
        incorrectExtensionType.modification = incorrectExtensionTypeModification
    }

    override val name: String
        get() = "grease_extension(greaseType=$greaseType, enable=$enable)"
}