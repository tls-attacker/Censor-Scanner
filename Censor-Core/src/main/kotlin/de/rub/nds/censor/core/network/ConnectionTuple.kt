package de.rub.nds.censor.core.network

data class ConnectionTuple(val ip1: String, val port1: Int, val ip2: String, val port2: Int, val tcp: Boolean) {
    override fun equals(other: Any?): Boolean {
        if (other !is ConnectionTuple) return false // not same class
        if (ip1 == other.ip1 && port1 == other.port1 && ip2 == other.ip2 && port2 == other.port2 && tcp == other.tcp) return true // all equal
        if (ip1 == other.ip2 && port1 == other.port2 && ip2 == other.ip1 && port2 == other.port1 && tcp == other.tcp) return true // swapped ports and ips
        return false
    }

    override fun hashCode(): Int {
        return ip1.hashCode() + port1 + ip2.hashCode() + port2 + tcp.hashCode()
    }
}
