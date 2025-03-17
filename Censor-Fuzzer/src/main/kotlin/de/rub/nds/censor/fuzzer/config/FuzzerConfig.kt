package de.rub.nds.censor.fuzzer.config

import com.beust.jcommander.Parameter
import com.beust.jcommander.ParameterException
import com.beust.jcommander.ParametersDelegate
import de.rub.nds.censor.core.config.Delegate
import de.rub.nds.censor.core.config.GeneralDelegate
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.Port
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.network.Ipv4Address
import de.rub.nds.censor.core.network.Ipv6Address
import kotlinx.serialization.Transient
import kotlin.properties.Delegates

class FuzzerConfig: Delegate {

    @Parameter(
        names = ["-scanType"],
        required = true,
        description = "Whether to scan a TLS server or censorship to an ECHO server"
    )
    var scanType: CensorScanType = CensorScanType.DIRECT

    @Parameter(
        names = ["-connect"],
        required = true,
        description = "Who to connect to. Syntax: ip:port"
    )
    private var host: String = "127.0.0.1:443"

    @Parameter(
        names = ["-serverName"],
        required = true,
        description = "Server name for the SNI extension."
    )
    var hostname: String = "target.com"

    @Parameter(
        names = ["-timeout"],
        required = false,
        description = "The timeout used for the scans in ms (default 5000)"
    )
    var timeout = 5000

    @Parameter(
        names = ["-keyLogFile"],
        required = false,
        description = "Location of the file key material will be saved to"
    )
    var keyLogFile = ""

    @Parameter(
        names = ["-outputFileIdentifier"],
        required = false,
        description = "Identifier that the output files name of the analysis will be prepended with. Default is results/unspecified_server, resulting in for example results/unspecified-server_strength_2_results.txt"
    )
    var outputFileIdentifier = "results/unspecified-server"

    @Parameter(
        names = ["-interface"],
        required = false,
        description = "Network Interface to capture traffic on"
    )
    var networkInterface = "any"

    @Parameter(
        names = ["-enableCapturing"],
        required = false,
        description = "If true, enables connection analysis with pcap4j. Java needs network capabilities (or sudo) in" +
                "this case."
    )
    var enableCapturing = false

    @Parameter(
        names = ["-testStrength"],
        required = false,
        description = "Test strength for the fuzzer",
    )
    var testStrength = 3

    @Parameter(
        names = ["-threads"],
        required = false,
        description = "How many threads to use in parallelized connections"
    )
    var threads = 100

    @Parameter(
        names = ["-exclude"],
        required = false,
        description = "Which (group of) strategies to exclude. Default is None (not present) - indicates that all should be used. Add multiple groups by " +
                "separating them with commas."
    )
    var excludeStrategies = listOf(ExcludeStrategies.NONE)

    @Parameter(
        names = ["-writeAllResultTypes"],
        required = false,
        description = "If true, writes all result types into the file. Otherwise, unnecessary result types for further analysis are not written." +
                "Examples for not written types are already default and inapplicable."
    )
    var writeAllResultTypes = false

    @Parameter(
        names = ["-testVectorInputFile"],
        required = false,
        description = "If set, deserializes the given file into a set of Test vectors to use instead of the generated " +
                "default list. Overrides -excludeStrategies and -testStrength. Optional, but if set fails on" +
                "serialization errors."
    )
    var testVectorInputFile: String? = null

    @Parameter(
        names = ["-simpleScanServerAnswerBytes"],
        required = false,
        description = "Bytes sent by a vantage point server for the SimpleScan type. Provide in hex"
    )
    var simpleScanServerAnswerBytes = "6565656565"

    @ParametersDelegate
    @Transient
    val generalDelegate = GeneralDelegate()

    lateinit var extractedIp: IpAddress
    var extractedPort by Delegates.notNull<Int>()

    override fun apply() {
        generalDelegate.apply()

        // extract host and port
        if (!host.contains(":")) {
            throw ParameterException("Format of -connect parameter invalid. Use <ip>:<port>")
        }
        val rawIp = host.substringBeforeLast(":")
        val rawPort = host.substringAfterLast(":")

        // extract host ip
        extractedIp = try {
            Ipv4Address(rawIp)
        } catch (e: Exception) {
            try {
                Ipv6Address(rawIp)
            } catch (e: Exception) {
                throw ParameterException("$rawIp cannot be parsed as valid ipv4 or ipv6")
            }
        }

        // extract port
        extractedPort = try {
            rawPort.toInt()
        } catch (e: NumberFormatException) {
            throw ParameterException("$rawPort cannot be parsed as integer")
        }
        if (!Port.isValid(extractedPort)) {
            throw ParameterException("$rawPort not in port range [${Port.MIN}, ${Port.MAX}]")
        }
    }

    fun toHumanReadable(): String {
        return "FuzzerConfig(\n" +
                "host='$host',\n" +
                "hostname='$hostname',\n" +
                "timeout=$timeout,\n" +
                "keyLogFile='$keyLogFile',\n" +
                "outputFileIdentifier='$outputFileIdentifier',\n" +
                "networkInterface='$networkInterface',\n" +
                "enableCapturing=$enableCapturing,\n" +
                "testStrength=$testStrength,\n" +
                "threads=$threads,\n" +
                "excludeStrategies=$excludeStrategies,\n" +
                "writeAllResultTypes=$writeAllResultTypes,\n" +
                "testVectorInputFile=$testVectorInputFile,\n" +
                "generalDelegate=$generalDelegate,\n" +
                "extractedIp=$extractedIp,\n" +
                "extractedPort=$extractedPort,\n)"
    }
}