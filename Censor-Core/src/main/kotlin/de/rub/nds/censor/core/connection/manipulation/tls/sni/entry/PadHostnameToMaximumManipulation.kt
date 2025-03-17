package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.constants.ManipulationConstants
import de.rub.nds.tlsattacker.core.config.Config

/**
 * Pads the hostname at the given index to maximum size
 */
class PadHostnameToMaximumManipulation(private val entry: Int) : SniEntryManipulation(entry) {
    override val name: String
        get() = "pad_to_max(entry=$entry)"

    override fun afterConfigInit(tlsConfig: Config) {
        val serverNamePair = getServerNamePair(tlsConfig)
        val hostname = serverNamePair.serverNameConfig

        var sizeLeftForSNI = ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE - 5001
        tlsConfig.defaultSniHostnames.forEachIndexed { index, sni ->
            if (index != entry) {
                sizeLeftForSNI -= sni.serverNameConfig.size
            }
        }
        val paddedHostname = ByteArray(sizeLeftForSNI)
        hostname.forEachIndexed { index, byte -> paddedHostname[index] = byte }
        paddedHostname.forEachIndexed { index, _ -> if (index >= hostname.size) paddedHostname[index] = 0x71 }

        serverNamePair.serverNameConfig = paddedHostname
    }
}