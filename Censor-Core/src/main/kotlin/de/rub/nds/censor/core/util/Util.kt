package de.rub.nds.censor.core.util

import de.rub.nds.censor.core.constants.*
import de.rub.nds.censor.core.exception.NotFoundException
import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.constants.SniType
import de.rub.nds.tlsattacker.core.protocol.message.CoreClientHelloMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.ServerNameIndicationExtensionMessage
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair
import de.rub.nds.tlsattacker.core.record.Record
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace
import de.rub.nds.tlsattacker.core.workflow.action.SendAction
import de.rub.nds.x509attacker.x509.model.X509Certificate
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer
import org.apache.logging.log4j.kotlin.KotlinLogger
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.util.*


object Util {

    private var ipToInternet: String = ""
        get() {
            if (field == "") {
                field = getDefaultSrcIpFor(Ip.GOOGLE_DNS_1.ipAddress.address)
            }
            return field
        }

    private var ipToLocalhost: String = ""
        get() {
            if (field == "") {
                field = getDefaultSrcIpFor("127.0.0.1")
            }
            return field
        }

    /**
     * Returns the src ip for the connection to the given ip. Defaults to Google's DNS server for internet access.
     */
    private fun getDefaultSrcIpFor(ip: String): String {
        DatagramSocket().use { socket ->
            try {
                socket.connect(InetAddress.getByName(ip), Port.DNS.portNumber)
            } catch (e: Exception) {
                // its unimportant if we cannot connect to the server, we only need the src ip to be assigned from
                // routing tables
            }
            return socket.localAddress.hostAddress
        }
    }

    /**
     * Returns the local ip on this device for the given ipv4Address.
     */
    fun getSrcIp(ip: IpAddress): String {
        return if (ip.isLocalhost()) {
            ipToLocalhost
        } else {
            ipToInternet
        }
    }

    /**
     * Returns whether the hostname is in the given certificate
     */
    fun X509Certificate.containsHostname(hostname: String, logger: KotlinLogger): Boolean {

        val names = mutableListOf<String>()

        names.add(commonName)
        // TODO: re-add when implemented in x509 attacker
        // names.addAll(subjectAlternativeNames)
        try {
            val holder = X509CertificateHolder(X509Asn1FieldSerializer(this).serialize())
            val convertedCert = JcaX509CertificateConverter().getCertificate(holder)
            // add all alternative names
            convertedCert?.subjectAlternativeNames?.forEach { name -> name[1]?.toString()?.also { names.add(it) } }
        } catch (e: Exception) {
            logger.warn("Could not parse certificate with exception: ", e)
            return false
        }



        return !names.find {
            hostnameInWildcard(hostname, it, logger)
        }.isNullOrEmpty()
    }

    /**
     * Returns whether the given hostname is contained in the wildcard. Wildcard can be a hostname or wildcard
     * (i.e. *.upb.de). Assumes * to appear at maximum once in the wildcard as the leftmost part (i.e. www.*.upb.de) will
     * be rejected.
     */
    private fun hostnameInWildcard(hostname: String, wildcard: String, logger: KotlinLogger): Boolean {

        val wildcards = (wildcard.filter { it == '*' }.length)

        if (wildcards > 1) {
            logger.error("Too many * in wildcard hostname $wildcard.")
            return false
        } else if (wildcards == 1 && wildcard[0] != '*') {
            logger.error("* not in first place of wildcard")
            return false
        }

        val partsHostname = hostname.split(".").reversed().toMutableList()
        val partsWildcard = wildcard.split(".").reversed()

        // the hostname must contain all parts of the hostname
        partsWildcard.forEach { partWildcard ->

            if (partsHostname.isEmpty()) {
                // not all wildcard subdomains matched
                return false
            }

            if (partWildcard == "*") {
                // done
                return true
            }
            val partHostname = partsHostname.removeAt(0)
            if (partHostname != partWildcard) {
                return false
            }
        }
        // subdomain
        return partsHostname.isEmpty()
    }

    fun WorkflowTrace.getClientHelloMessage(): CoreClientHelloMessage {
        sendingActions.filterIsInstance<SendAction>().forEach { messageAction ->
            return messageAction.configuredMessages?.
            find { it is CoreClientHelloMessage }.
            let { it as CoreClientHelloMessage }
        }
        throw NotFoundException("Could not find ClientHelloMessage in WorkflowTrace")
    }

    fun WorkflowTrace.getExtensions(): MutableList<ExtensionMessage> {
        getClientHelloMessage().extensions?.also { return it }

        throw NotFoundException("Could not extract extensions from WorkflowTrace")
    }

    fun WorkflowTrace.getExtension(
        tlsExtension: Class<out ExtensionMessage>
    ): ExtensionMessage {
        getClientHelloMessage().getExtension(tlsExtension)?.also { return it }

        throw NotFoundException("Could not find $tlsExtension in WorkflowTrace")
    }

    fun WorkflowTrace.getSniExtension(): ServerNameIndicationExtensionMessage {
        return getExtension(ServerNameIndicationExtensionMessage::class.java)
                as ServerNameIndicationExtensionMessage
    }

    fun CoreClientHelloMessage.getParsedExtensionsLengthWithoutLast(): Int {
        return extensions
            //all but last
            .subList(0, extensions.size - 1)
            // add extension length plus headers
            .sumOf { extension ->
                extension.extensionLength.value + ManipulationConstants.TLS_EXTENSION_HEADER
            }
    }

    /**
     * Calculates the serialized length of all extensions up the first SNI message. Raises an illegal argument exception
     * if no SNI is present
     */
    @Throws(IllegalArgumentException::class)
    fun CoreClientHelloMessage.getParsedExtensionsUntilFirstSni(): Int {
        if (extensions.find { it is ServerNameIndicationExtensionMessage } == null) {
            throw java.lang.IllegalArgumentException("No SNI present")
        }
        return extensions
            //all until SNI
            .subList(0, extensions.indexOfFirst { it is ServerNameIndicationExtensionMessage })
            // add extension length plus headers
            .sumOf { extension ->
                extension.extensionLength.value + ManipulationConstants.TLS_EXTENSION_HEADER
            }
    }

    fun Config.addSniEntry(hostname: String, amount: Int = 1) {
        (0..<amount).forEach { _ ->
            defaultSniHostnames
                .add(
                    ServerNamePair(
                        SniType.HOST_NAME.value,
                        hostname.toByteArray(StandardCharsets.US_ASCII)
                    )
                )
        }
    }

    /**
     * New Int util function that allows us to convert an Int to a hex string while specifying the number of bytes to obtain.
     * Substring is done from right to left depending on the number of bytes.
     */
    @OptIn(ExperimentalStdlibApi::class)
    fun Int.toHexString(byteSize: Int): String {
        var hexString = toHexString()
        hexString = hexString.substring(hexString.length - byteSize * 2)
        return hexString
    }

    private fun Record.setNullByteAsContent() {
        setCleanProtocolMessageBytes(byteArrayOf(0x00))
    }

    private fun Record.setCorrectCCSBytes() {
        setCleanProtocolMessageBytes(byteArrayOf(1.toByte()))
    }

    private fun Record.setIncorrectCCSBytes() {
        setCleanProtocolMessageBytes(byteArrayOf(2.toByte()))
    }

    private fun Record.setInternalErrorWarningAlertBytes() {
        setCleanProtocolMessageBytes(byteArrayOf(1.toByte(), 80.toByte())) // warning(1), internal error(80)
    }

    private fun Record.setInternalErrorFatalAlertBytes() {
        setCleanProtocolMessageBytes(byteArrayOf(2.toByte(), 80.toByte())) // fatal(1), internal error(80)
    }

    private fun Record.setIncompleteAlertBytes() {
        setCleanProtocolMessageBytes(byteArrayOf(1.toByte())) // warning(1) --> missing alert description field
    }

    private fun Record.setHeartbeatRequestBytes() {
        setCleanProtocolMessageBytes(byteArrayOf(1.toByte(), 0.toByte(), 2.toByte(), 0x41, 0x41, // heartbeat_request(1), payload_length(2 byte), payload (2 bytes)
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20)) // padding(16 bytes)
    }

    private fun Record.setHeartbeatResponseBytes() {
        setCleanProtocolMessageBytes(byteArrayOf(2.toByte(), 0.toByte(), 2.toByte(), 0x41, 0x41, // heartbeat_response(2), payload_length(2 byte), payload (2 bytes)
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20)) // padding(16 bytes)
    }

    private fun Record.setHeartbeatIncompleteBytes() {
        setCleanProtocolMessageBytes(byteArrayOf(1.toByte(), 0.toByte(), 5.toByte(), 0x41, 0x41)) // heartbeat_request(1), payload_length(5 byte), payload (2 bytes, too short), missing padding
    }

    fun Record.applyManipulationType(type: RecordManipulationType) {
        when (type) {
            RecordManipulationType.INVALID_TYPE -> setNullByteAsContent()
            RecordManipulationType.CHANGE_CIPHER_SPEC_VALID -> setCorrectCCSBytes()
            RecordManipulationType.CHANGE_CIPHER_SPEC_INVALID -> setIncorrectCCSBytes()
            RecordManipulationType.ALERT_INCOMPLETE -> setIncompleteAlertBytes()
            RecordManipulationType.ALERT_INTERNAL_WARN -> setInternalErrorWarningAlertBytes()
            RecordManipulationType.ALERT_INTERNAL_FATAL -> setInternalErrorFatalAlertBytes()
            RecordManipulationType.HANDSHAKE_NULL_BYTE -> setNullByteAsContent()
            RecordManipulationType.APPLICATION_DATA_NULL_BYTE -> setNullByteAsContent()
            RecordManipulationType.HEARTBEAT_REQUEST -> setHeartbeatRequestBytes()
            RecordManipulationType.HEARTBEAT_RESPONSE -> setHeartbeatResponseBytes()
            RecordManipulationType.HEARTBEAT_INCOMPLETE -> setHeartbeatIncompleteBytes()
        }
    }
}