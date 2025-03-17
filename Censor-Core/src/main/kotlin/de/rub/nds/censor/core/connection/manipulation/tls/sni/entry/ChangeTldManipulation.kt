package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.tlsattacker.core.config.Config

/**
 * Change the top-level domain of the SNI hostname.
 */
class ChangeTldManipulation(private val entry: Int, val tld: String) : SniEntryManipulation(entry) {

    override val name: String
        get() = "change_tld(entry=$entry, tld=$tld)"

    override fun afterConfigInit(tlsConfig: Config) {
        val serverNamePair = getServerNamePair(tlsConfig)

        val hostname = serverNamePair.serverNameConfig.decodeToString()
        val lastTld = hostname.substringAfterLast(".")
        if (lastTld == tld) {
            // do not execute connection where we do not change the TLD
            throw NotConnectableException(ConnectionReturn.ALREADY_DEFAULT, "Tld is already $tld")
        }
        serverNamePair.serverNameConfig = (hostname.substringBeforeLast('.') + '.' + tld).encodeToByteArray()
    }
}