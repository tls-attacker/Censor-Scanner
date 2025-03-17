package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair

/**
 * Abstract class for manipulations that operate on a specific SNI index.
 */
abstract class SniEntryManipulation(private val sniEntryIndex: Int) : TlsManipulation() {

    /**
     * Gets the correct hostname in the SNI based on the given index
     */
    protected fun getServerNamePair(tlsConfig: Config): ServerNamePair {
        return tlsConfig.defaultSniHostnames[getListIndexForSniIndex(tlsConfig, sniEntryIndex)]
    }

    /**
     * Allows for -x to indicate entries from the back and Int.MAX_VALUE to indicate the middle
     */
    protected fun getListIndexForSniIndex(tlsConfig: Config, sniEntryIndex: Int): Int {
        return if (sniEntryIndex == Int.MAX_VALUE) {
            tlsConfig.defaultSniHostnames.size / 2
        } else if (sniEntryIndex >= 0) {
            sniEntryIndex
        } else {
            tlsConfig.defaultSniHostnames.size + sniEntryIndex
        }
    }
}