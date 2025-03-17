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

import de.rub.nds.censor.core.connection.BasicTlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.EncryptedClientHelloVersion
import de.rub.nds.censor.core.util.Util.getExtension
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloExtensionMessage
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace
import java.nio.charset.StandardCharsets

/**
 * Adds an ECH extension to the connection with the provided version bytes of the newer ech
 * extension.
 */
class EchExtensionManipulation(
    private val hostName: String,
    val echVersion: EncryptedClientHelloVersion,
    val enable: Boolean
) : TlsManipulation() {

    override fun afterConfigInit(tlsConfig: Config) {
        // add ech extension
        tlsConfig.isAddEncryptedClientHelloExtension = enable
        if (enable) {
            // set plaintext hostname of outer client hello
            tlsConfig.defaultEchConfig!!.publicDomainName = hostName.toByteArray(StandardCharsets.US_ASCII)
        }
    }

    override fun afterWorkflowTrace(
        workflowTrace: WorkflowTrace, tlsConnection: BasicTlsConnection, config: Config
    ) {
        if (enable) {
            // override echVersion version if necessary
            val incorrectExtensionType = ModifiableByteArray()
            val incorrectExtensionTypeModification = ByteArrayExplicitValueModification()
            incorrectExtensionTypeModification.explicitValue = echVersion.versionBytes
            workflowTrace.getExtension(EncryptedClientHelloExtensionMessage::class.java)
                .extensionType = incorrectExtensionType
            incorrectExtensionType.modification = incorrectExtensionTypeModification
        }
    }

    override val name: String
        get() = "ech_extension(echVersion=$echVersion, enable=$enable)"
}