package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.tlsattacker.core.config.Config

/**
 * Reverses the letters of the hostname in the SNI extension.
 */
class ReverseManipulation(private val entry: Int) : SniEntryManipulation(entry) {

    override val name: String
        get() = "reverse(entry=$entry)"

    override fun afterConfigInit(tlsConfig: Config) {
        val serverNamePair = getServerNamePair(tlsConfig)
        serverNamePair.serverNameConfig = serverNamePair.serverNameConfig.reversedArray()
    }
}
