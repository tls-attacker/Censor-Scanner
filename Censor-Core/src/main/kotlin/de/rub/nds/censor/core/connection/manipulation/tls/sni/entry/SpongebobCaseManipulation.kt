package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.tlsattacker.core.config.Config
import java.nio.charset.StandardCharsets
import java.util.*

/**
 * Changes the hostname to sPoNgEbObCaSe
 */
class SpongebobCaseManipulation(private val entry: Int) : SniEntryManipulation(entry) {
    override val name: String
        get() = "spongebobcase(entry=$entry)"

    override fun afterConfigInit(tlsConfig: Config) {
        val serverNamePair = getServerNamePair(tlsConfig)
        val hostname = serverNamePair.serverNameConfig

        val newHostname = hostname.toString(StandardCharsets.US_ASCII).lowercase(Locale.getDefault()).toCharArray()
        var position = 1
        while (position < newHostname.size) {
            newHostname[position] = newHostname[position].uppercaseChar()
            position += 2
        }

        serverNamePair.serverNameConfig = String(newHostname).toByteArray()
    }
}