package de.rub.nds.censor.core.data

import de.rub.nds.censor.core.network.IpAddress
import kotlinx.serialization.Serializable

/**
 * Represents the connection to a server in regard to ip, hostname, and port
 */
@Serializable
data class ServerAddress(val ip: IpAddress, val port: Int, val hostname: String) {
    override fun toString(): String {
        return "$ip:$port:$hostname"
    }
}