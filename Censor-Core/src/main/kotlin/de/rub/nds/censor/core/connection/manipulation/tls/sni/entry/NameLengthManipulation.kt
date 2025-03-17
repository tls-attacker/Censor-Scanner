/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2023
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.modifiablevariable.integer.IntegerExplicitValueModification
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage

/**
 * Changes the server name length of a list entry in the SNI extension
 * */
class NameLengthManipulation(val entry: Int, val length: Int) : SniEntryManipulation(entry) {
    override val name: String
        get() = "nameLength(length=$length)"

    override fun betweenMessagePreparation(message: ProtocolMessage, tlsConfig: Config) {
        if (message !is CoreClientHelloMessage) {
            logger.error("Can only set name length to SNI-dependant value in ClientHello messages, skipping")
            return
        }

        val sni = message.getExtension(ServerNameIndicationExtensionMessage::class.java)
        val entryHostname = sni.serverNameList[getListIndexForSniIndex(tlsConfig, entry)]
        val explicitModification = IntegerExplicitValueModification()
        explicitModification.explicitValue = length
        if (explicitModification.explicitValue == entryHostname.serverNameLength.value) {
            throw NotConnectableException(ConnectionReturn.ALREADY_DEFAULT, "Name length is already ${explicitModification.explicitValue}")
        }
        entryHostname.serverNameLength.modification = explicitModification
    }
}