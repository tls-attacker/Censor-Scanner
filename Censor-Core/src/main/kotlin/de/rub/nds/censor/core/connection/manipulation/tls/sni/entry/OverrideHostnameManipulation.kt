package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.tlsattacker.core.config.Config

/**
 * Overrides the hostname in the SNI extension.
 */
class OverrideHostnameManipulation(private val entry: Int, val hostname: String) : SniEntryManipulation(entry) {

    override val name: String
        get() = "override_hostname(entry=$entry, hostname=$hostname)"

    override fun afterConfigInit(tlsConfig: Config) {
        getServerNamePair(tlsConfig).serverNameConfig = hostname.encodeToByteArray()
    }
}