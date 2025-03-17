package de.rub.nds.censor.core.util

import de.rub.nds.censor.core.connection.HttpsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.AdditionalEntryManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.length.list.ListLengthManipulation
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.network.Ipv4Address
import de.rub.nds.tlsattacker.core.util.ProviderUtil
import kotlinx.coroutines.runBlocking

fun main() {

    ProviderUtil.addBouncyCastleProvider()

    val ip = Ipv4Address("")
    val port = 443
    val timeout = 2000
    val hostname = ""
    val pcapCapturer = PcapCapturer(interfaceName = "any", bpfExpression = "tcp or udp")
    val keyLogFile = "/tmp/key.log"

    val httpsConnection = HttpsConnection(
    ip = ip,
    serverPort = port,
    timeout = timeout,
    censorScanType = CensorScanType.DIRECT,
    hostname = hostname,
    pcapCapturer = pcapCapturer,
    keyLogFilePath = keyLogFile
    )

    val manipulations = listOf(
        SniExtensionManipulation(hostName = hostname, enable = true),
        ListLengthManipulation(0.5),
        AdditionalEntryManipulation(hostname, 1)
    )

    httpsConnection.registerManipulations(manipulations)
    runBlocking {
        httpsConnection.connect()
    }
    print(httpsConnection.firstHttpResponse?.responseContent)
}