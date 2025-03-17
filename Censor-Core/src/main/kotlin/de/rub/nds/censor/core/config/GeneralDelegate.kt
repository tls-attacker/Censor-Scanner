package de.rub.nds.censor.core.config

import com.beust.jcommander.Parameter
import de.rub.nds.tlsattacker.core.util.ProviderUtil
import org.apache.logging.log4j.Level
import org.apache.logging.log4j.core.config.Configurator
import org.apache.logging.log4j.kotlin.Logging
import java.security.Security

open class GeneralDelegate : Delegate {

    @Parameter(
        names = ["-h", "-help"],
        help = true,
        description = "Prints usage for all the existing commands."
    )
    var help = false

    @Parameter(
        names = ["-debug"],
        description = "Show extra debug output (sets logLevel to DEBUG)"
    )
    var debug = false

    @Parameter(
        names = ["-quiet"],
        description = "No output (sets logLevel to NONE)"
    )
    var quiet = false

    override fun apply() {
        ProviderUtil.addBouncyCastleProvider()
        if (debug) {
            Configurator.setAllLevels("de.rub.nds.censor", Level.DEBUG)
        } else if (quiet) {
            Configurator.setAllLevels("de.rub.nds.censor", Level.OFF)
        }
        logger.debug("Using the following security providers")
        for (p in Security.getProviders()) {
            logger.debug("Provider ${p.name}, version, ${p.info}")
        }
    }

    companion object : Logging
}