/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.tlsattacker.core.config.Config

/**
 * Changes the name type of the SNI hostname to a different byte than 0. The ServerNameIndication
 * extension allows for potentially other name types than hostnames to be used. Still, it does not
 * specify their usage.
 */
class NameTypeManipulation(entry: Int, val nameType: Byte) : SniEntryManipulation(entry) {
    override val name: String
        get() = "name_type($nameType)"

    override fun afterConfigInit(tlsConfig: Config) {
        val serverNamePair = getServerNamePair(tlsConfig)
        serverNamePair.setServerNameType(nameType)
        serverNamePair.serverNameTypeConfig = nameType
    }
}