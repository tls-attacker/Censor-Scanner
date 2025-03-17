package de.rub.nds.censor.fuzzer.main

import com.beust.jcommander.JCommander
import com.beust.jcommander.ParameterException
import de.rub.nds.censor.core.constants.CensorScanType
import de.rub.nds.censor.fuzzer.config.FuzzerConfig
import de.rub.nds.censor.fuzzer.data.ServerEvaluation
import de.rub.nds.censor.fuzzer.execution.EchoServerTlsCensorshipScanner
import de.rub.nds.censor.fuzzer.execution.SimpleTlsCensorshipScanner
import de.rub.nds.censor.fuzzer.execution.TlsServerScanner
import de.rub.nds.censor.fuzzer.execution.port.ChinaPortProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import org.apache.logging.log4j.LogManager

@OptIn(ExperimentalCoroutinesApi::class)
fun main(args: Array<String>) {
    val config = FuzzerConfig()
    val jCommander = JCommander(config)
    try {
        jCommander.parse(*args)
        config.apply()
    } catch (e: ParameterException) {
        LogManager.getLogger().error(e)
        jCommander.usage()
        return
    }

    val scanner = when (config.scanType) {

        CensorScanType.DIRECT -> TlsServerScanner(
            fuzzerConfig = config,
            dispatcher = Dispatchers.IO.limitedParallelism(config.threads),
            serverEvaluation = ServerEvaluation.fromConfig(config)
        )

        CensorScanType.ECHO -> EchoServerTlsCensorshipScanner(
            fuzzerConfig = config,
            dispatcher = Dispatchers.IO.limitedParallelism(config.threads),
            serverEvaluation = ServerEvaluation.fromConfig(config)
        )

        CensorScanType.SIMPLE -> SimpleTlsCensorshipScanner(
            fuzzerConfig = config,
            dispatcher = Dispatchers.IO.limitedParallelism(config.threads),
            serverEvaluation = ServerEvaluation.fromConfig(config)
        )
    }

    scanner.execute()
}