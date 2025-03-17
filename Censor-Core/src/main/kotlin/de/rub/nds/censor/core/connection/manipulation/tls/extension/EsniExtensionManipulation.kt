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

/** Adds an ESNI extension to the connection.  */
class EsniExtensionManipulation(val enable: Boolean) : TlsManipulation() {

    override fun afterConfigInit(tlsConfig: Config) {
        tlsConfig.isAddEncryptedServerNameIndicationExtension = enable
    }

    override val name: String
        get() = "esni_extension(enable=$enable)"
}