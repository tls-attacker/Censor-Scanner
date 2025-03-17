package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.tlsattacker.core.config.Config
import java.nio.charset.StandardCharsets

/**
 * Sets the character in the given position to uppercase.
 */
class CapitalizationManipulation(private val entry: Int, val positions: List<Int>) :
    SniEntryManipulation(entry) {

    override val name: String
        get() = "capitalization(entry=$entry, positions=$positions)"

    override fun afterConfigInit(tlsConfig: Config) {
        val serverNamePair = getServerNamePair(tlsConfig)
        val hostname = serverNamePair.serverNameConfig

        val newHostname = hostname.toString(StandardCharsets.US_ASCII).toCharArray()
        positions.forEach { position ->
            if (newHostname.size <= position) {
                logger.warn("Position $position is out of bounds for hostname ${serverNamePair.serverNameConfig}.")
            }
            newHostname[position] = newHostname[position].uppercaseChar()
        }
        serverNamePair.serverNameConfig = String(newHostname).toByteArray()
    }
}