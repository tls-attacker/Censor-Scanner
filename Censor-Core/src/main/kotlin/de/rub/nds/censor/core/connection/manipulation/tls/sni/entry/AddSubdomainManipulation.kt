package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.tlsattacker.core.config.Config

/**
 * Adds a subdomain to the SNI extension's hostname
 */
class AddSubdomainManipulation(private val entry: Int, val subdomain: String) : SniEntryManipulation(entry) {

    override val name: String
        get() = "add_subdomain(entry=$entry, subdomain=$subdomain)"

    override fun afterConfigInit(tlsConfig: Config) {
        val serverNamePair = getServerNamePair(tlsConfig)
        val hostname = serverNamePair.serverNameConfig.decodeToString()

        serverNamePair.serverNameConfig = ("$subdomain.$hostname").encodeToByteArray()
    }
}