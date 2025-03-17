package de.rub.nds.censor.core.util

import de.rub.nds.censor.core.constants.Ip
import de.rub.nds.censor.core.network.Ipv4Address
import de.rub.nds.x509attacker.x509.model.X509Certificate
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class UtilTest {

    @Test
    fun getSrcIp() {

        // check whether we connect to localhost over localhost
        val localSrcIp = Util.getSrcIp(Ipv4Address("127.0.0.1"))
        assertEquals("127.0.0.1", localSrcIp)

        // check that we have some IP address to the Internet
        val internetSrcIp = Util.getSrcIp(Ipv4Address(Ip.GOOGLE_DNS_1.ipAddress.address))
        Ipv4Address(internetSrcIp)
    }

    @Test
    fun keepTrackOfSanImplementationX509() {
        val cert = X509Certificate("tbsCertificate")
        try {
            cert.subjectAlternativeNames
        } catch (e: UnsupportedOperationException) {
            assertEquals("getSubjectAlternativeNames not implemented yet", e.message)
            return
        }
        throw AssertionError("SubjectAlternativeName implementation in x509 attacker changed!")
    }
}