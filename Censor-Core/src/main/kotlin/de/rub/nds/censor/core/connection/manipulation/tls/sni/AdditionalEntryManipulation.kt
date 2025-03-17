/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tls.sni

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.constants.SniType
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair
import java.nio.charset.StandardCharsets

/** Adds additional SNI hostnames to the SNI extension.
 */
class AdditionalEntryManipulation(val hostName: String, val amount: Int) : TlsManipulation() {
    override val name: String
        get() = "additional_list_entry(name=$hostName)"

    override fun afterConfigInit(tlsConfig: Config) {
        (0..<amount).forEach { _ ->
            tlsConfig
                .defaultSniHostnames
                .add(
                    ServerNamePair(
                        SniType.HOST_NAME.value,
                        hostName.toByteArray(StandardCharsets.US_ASCII)
                    )
                )
        }
    }
}