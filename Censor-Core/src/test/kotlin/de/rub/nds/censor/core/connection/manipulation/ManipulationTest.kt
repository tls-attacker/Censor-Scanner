package de.rub.nds.censor.core.connection.manipulation

import de.rub.nds.censor.core.connection.TlsConnection
import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.connection.manipulation.tls.extension.SniExtensionManipulation
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.core.constants.Ip
import de.rub.nds.censor.core.network.Ipv4Address
import de.rub.nds.censor.core.util.EchoServer
import de.rub.nds.censor.core.util.LengthCalculator
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage
import de.rub.nds.tlsattacker.core.record.Record
import de.rub.nds.tlsattacker.core.util.ProviderUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.TestScope
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
abstract class ManipulationTest<Manipulation : TlsManipulation>(private val fails: Boolean = false) {

    protected val defaultMessageLength: Int
        get() = lengthCalculator.messageLength
    protected val defaultExtensionsLength: Int
        get() = lengthCalculator.extensionsLength
    protected val defaultSniExtensionLength: Int
        get() = lengthCalculator.sniExtensionLength
    protected val defaultSniListLength: Int
        get() = lengthCalculator.sniListLength
    protected val defaultEcPointFormatsExtensionLength: Int
        get() = lengthCalculator.ecPointFormatsExtensionLength
    protected val defaultSupportedGroupsExtensionLength: Int
        get() = lengthCalculator.supportedGroupsExtensionLength
    protected val defaultSignatureAlgorithmExtensionLength: Int
        get() = lengthCalculator.signatureAlgorithmExtensionLength
    protected val defaultCipherSuitesLength: Int
        get() = lengthCalculator.cipherSuitesLength
    protected val defaultExtensionCount: Int
        get() = lengthCalculator.extensionsCount


    /**
     * Tests all manipulations by opening a [TlsConnection] to a locally running ECHO server.
     */
    @ParameterizedTest
    @MethodSource("targetManipulations")
    fun parametrizedTest(manipulation: Manipulation) {

        // setup connections
        val tlsConnection = TlsConnection(
            Ip.LOCALHOST.ipAddress,
            echoServer.port,
            1000,
            CensorScanType.ECHO
        )

        // add specific manipulation
        tlsConnection.manipulations.addAll(extraManipulations())
        tlsConnection.manipulations.add(manipulation)
        // connect to server
        try {
            runBlocking {
                tlsConnection.connect()
            }
        } catch (e: Exception) {
            if (fails) {
                analyzeConnectionForTestCase(tlsConnection, manipulation, e)
                return
            } else {
                throw e
            }
        }
        // check if echoed data is correct
        analyzeConnectionForTestCase(tlsConnection, manipulation)
    }

    @Test
    open fun initializeExceptionsTest() {}

    /**
     * Manipulations used in the parametrized test
     */
    abstract fun targetManipulations(): Collection<Manipulation>

    /**
     * Extra manipulations for auxiliary functions (i.e. add an SNI Extension)
     */
    open fun extraManipulations(): Collection<TlsManipulation> {
        return listOf()
    }


    abstract fun analyzeConnectionForTestCase(connection: TlsConnection, manipulation: Manipulation, exception: Exception? = null)

    protected fun TlsConnection.getRecord(): Record {
        return state.workflowTrace.lastReceivingAction.receivedRecords[0]
    }

    protected fun TlsConnection.getClientHello(): ClientHelloMessage {
        return state.workflowTrace.lastReceivingAction.receivedMessages[0] as ClientHelloMessage
    }

    companion object {

        const val DEFAULT_TEST_HOSTNAME = "example.com"
        const val DEFAULT_TEST_REPLACEMENT_HOSTNAME = "www.wikipedia.org"
        private val testScope = TestScope()
        private var echoServer: EchoServer = EchoServer(dispatcher = Dispatchers.IO)
        var lengthCalculator: LengthCalculator

        init {
            ProviderUtil.addBouncyCastleProvider()
            lengthCalculator = LengthCalculator(
                TlsConnection(Ipv4Address("127.0.0.1"), 1111, 0, CensorScanType.ECHO)
                    .also { it.manipulations.add(SniExtensionManipulation(DEFAULT_TEST_HOSTNAME, true)) }
            )
            // TODO: cancel when all Manipulation tests are run
            testScope.launch(Dispatchers.IO) { echoServer.run() }
        }
    }
}
