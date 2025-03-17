package de.rub.nds.censor.core.connection.manipulation.tls.sni.entry

import de.rub.nds.tlsattacker.core.config.Config

/**
 * Injects a symbol at the set position in the SNI extension name field.
 */
class InjectSymbolsManipulation(private val entry: Int, var position: Int, val symbols: ByteArray) :
    SniEntryManipulation(entry) {

    override val name: String
        get() = "inject_symbol(symbol=$symbols, entry=$entry, position=$position)"

    override fun afterConfigInit(tlsConfig: Config) {
        val serverName = getServerNamePair(tlsConfig).serverNameConfig

        if (position > serverName.size) {
            //hostname has been modified by another manipulation --> default at end
            position = serverName.size
        }
        val initialPos = position
        var afterPos = position

        val newServerName = ByteArray(serverName.size + symbols.size)
        System.arraycopy(serverName, 0, newServerName, 0, afterPos)
        symbols.forEach {
            newServerName[afterPos] = it
            afterPos += 1
        }
        System.arraycopy(serverName, initialPos, newServerName, afterPos, serverName.size - initialPos)
        getServerNamePair(tlsConfig).serverNameConfig = newServerName
    }
}