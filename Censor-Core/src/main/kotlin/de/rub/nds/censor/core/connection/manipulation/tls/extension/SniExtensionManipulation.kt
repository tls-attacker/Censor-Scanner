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
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.constants.SniType
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair
import java.nio.charset.StandardCharsets
import java.util.*

/** Adds a Sever Name Indication to the connection that contains the provided server name.  */
class SniExtensionManipulation(val hostName: String, val enable: Boolean) : TlsManipulation() {
    override fun afterConfigInit(tlsConfig: Config) {
        tlsConfig.isAddServerNameIndicationExtension = enable
        if (enable) {
            tlsConfig.defaultSniHostnames = LinkedList(
                listOf(
                    ServerNamePair(SniType.HOST_NAME.value,
                        hostName.toByteArray(StandardCharsets.US_ASCII)
                    )
                )
            )
        }
    }

    override val name: String
        get() = "sni_extension(name=$hostName,enable=$enable)"
}