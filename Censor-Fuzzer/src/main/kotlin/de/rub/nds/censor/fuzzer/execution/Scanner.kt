package de.rub.nds.censor.fuzzer.execution

import de.rub.nds.censor.core.util.PcapCapturer
import de.rub.nds.censor.fuzzer.config.FuzzerConfig
import de.rub.nds.censor.core.data.ServerAddress
import de.rub.nds.censor.fuzzer.data.ServerEvaluation
import kotlinx.coroutines.CoroutineDispatcher

abstract class Scanner {
    abstract val dispatcher: CoroutineDispatcher
    abstract val fuzzerConfig: FuzzerConfig
    abstract val serverEvaluation: ServerEvaluation
    protected val timeout: Int by lazy { fuzzerConfig.timeout }
    protected val pcapCapturer by lazy {
        if (fuzzerConfig.enableCapturing) {
            PcapCapturer(interfaceName = fuzzerConfig.networkInterface, bpfExpression = "tcp or udp")
        } else {
            null
        }
    }

    abstract fun scanServer(
        server: ServerAddress,
        serverEvaluation: ServerEvaluation
    )

    fun execute() {
        pcapCapturer?.start()
        scanServer(
            server = serverEvaluation.server,
            serverEvaluation = serverEvaluation
        )
        pcapCapturer?.stop()
    }
}
