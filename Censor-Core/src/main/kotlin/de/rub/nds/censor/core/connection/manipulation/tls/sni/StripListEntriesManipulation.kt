package de.rub.nds.censor.core.connection.manipulation.tls.sni

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.tlsattacker.core.config.Config

/**
 * Removes all SNI entries.
 */
class StripListEntriesManipulation : TlsManipulation() {

    override fun afterConfigInit(tlsConfig: Config) {
        tlsConfig.defaultSniHostnames.clear()
    }

    override val name: String
        get() = "strip_list_entries"
}