package de.rub.nds.censor.fuzzer.scripts

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.AddCipherSuitesAsPaddingManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.PaddingExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.message.MessageVersionManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.sni.entry.NameTypeManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.version.TlsVersionManipulation
import de.rub.nds.censor.core.constants.Censor
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.ConnectionReturn
import de.rub.nds.censor.core.constants.ManipulationConstants
import de.rub.nds.censor.core.exception.NotConnectableException
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.network.Ipv4Address
import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.fuzzer.combination.instantiation.NameTypeInstantiation
import de.rub.nds.censor.fuzzer.combination.strategy.MessageVersionStrategy
import de.rub.nds.censor.fuzzer.combination.strategy.NameTypeStrategy
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import de.rub.nds.tlsattacker.core.util.ProviderUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlin.properties.Delegates
import kotlin.system.exitProcess

fun main(args: Array<String>) {

    val type = CensorScanType.DIRECT
    val pcapCapturer = PcapCapturer()

    lateinit var hostname: String
    lateinit var ip: IpAddress
    var port by Delegates.notNull<Int>()
    var timeout by Delegates.notNull<Int>()

    try {
        hostname = args[0]
        ip = Ipv4Address(args[1])
        port = args[2].toInt()
        timeout = args[3].toInt()
    } catch (e: Exception) {
        println("Usage: java -jar <name>.jar <hostname> <ip> <port> <timeout>")
        exitProcess(0)
    }

    println("Starting simple scan")

    // init
    ProviderUtil.addBouncyCastleProvider()
    pcapCapturer.start()

    val tests = mutableListOf(
        // TLS 1.3
        Pair("Ground Truth", TlsConnection(ip, port, timeout, type, pcapCapturer = pcapCapturer, hostname = hostname, keyLogFilePath = "/tmp/key.log")
            .also {
                    connection ->
                connection.registerManipulations(
                    SniExtensionManipulation(hostname, true))
            }),
        Pair("Tls 1.3", TlsConnection(ip, port, timeout, type, pcapCapturer = pcapCapturer, hostname = hostname, keyLogFilePath = "/tmp/key.log")
            .also {
                    connection ->
                connection.registerManipulations(
                    SniExtensionManipulation(hostname, true),
                    TlsVersionManipulation(ProtocolVersion.TLS13))
            }),
        Pair("Message Version SSL2", TlsConnection(ip, port, timeout, type, pcapCapturer = pcapCapturer, hostname = hostname, keyLogFilePath = "/tmp/key.log")
            .also {
                    connection ->
                connection.registerManipulations(SniExtensionManipulation(hostname, true))
                connection.registerManipulations(MessageVersionManipulation(ProtocolVersion.SSL2.value, ClientHelloMessage::class.java))
            }),
        Pair("Both", TlsConnection(ip, port, timeout, type, pcapCapturer = pcapCapturer, hostname = hostname, keyLogFilePath = "/tmp/key.log")
            .also {
                    connection ->
                connection.registerManipulations(SniExtensionManipulation(hostname, true),
                    TlsVersionManipulation(ProtocolVersion.TLS13))
                connection.registerManipulations(MessageVersionManipulation(ProtocolVersion.SSL2.value, ClientHelloMessage::class.java))
            }),
        Pair("Name Type", TlsConnection(ip, port, timeout, type, pcapCapturer = pcapCapturer, hostname = hostname, keyLogFilePath = "/tmp/key.log")
            .also {
                    connection ->
                connection.registerManipulations(SniExtensionManipulation(hostname, true))
                connection.registerManipulations(NameTypeManipulation(0, 0x01))
            }),
        Pair("Both", TlsConnection(ip, port, timeout, type, pcapCapturer = pcapCapturer, hostname = hostname, keyLogFilePath = "/tmp/key.log")
            .also {
                    connection ->
                connection.registerManipulations(SniExtensionManipulation(hostname, true),
                    TlsVersionManipulation(ProtocolVersion.TLS13))
                connection.registerManipulations(NameTypeManipulation(0, 0x01))
            }),
    )

    // run
    runBlocking {
        val deferredResults = tests.map { test ->
            async(Dispatchers.IO) {
                val result = try {
                    test.second.connect()
                    Pair(test.first, ConnectionReturn.WORKING)
                } catch (e: NotConnectableException) {
                    if (e.reason.indicatesSniCensorship(Censor.RUSSIA)) {
                        Pair(test.first, ConnectionReturn.CENSORED)
                    } else {
                        Pair(test.first, e.reason)
                    }
                } catch (e: Exception) {
                    Pair(test.first, ConnectionReturn.INTERNAL_ERROR)
                }
                println(result)
            }
        }
        deferredResults.toList().awaitAll()
    }
}