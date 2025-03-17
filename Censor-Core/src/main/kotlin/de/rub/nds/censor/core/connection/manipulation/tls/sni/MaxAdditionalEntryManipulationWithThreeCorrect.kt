package de.rub.nds.censor.core.connection.manipulation.tls.sni

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.constants.ManipulationConstants
import de.rub.nds.censor.core.util.Util.addSniEntry
import de.rub.nds.tlsattacker.core.config.Config

/**
 * Fills the SNI extension list with a large amount of values
 */
class MaxAdditionalEntryManipulationWithThreeCorrect(private val correctHostname: String, private val incorrectHostname: String): TlsManipulation() {

    override val name: String
        get() = "max_additional_sni_list_entries(correctHostname=$correctHostname, incorrectHostname=$incorrectHostname)"

    override fun afterConfigInit(tlsConfig: Config) {
        // sanity check that the first hostname is the correct one
        if (tlsConfig.defaultSniHostnames[0].serverNameConfig.decodeToString() != correctHostname) {
            logger.error("First SNI entry not already default value!")
            return
        }
        // calculate incorrect hostnames
        val newEntryAmount =
            // max extension length
            ((ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE -
                // list length
                ManipulationConstants.SNI_LIST_LENGTH_LENGTH -
                // three correct entries
                (3 * (ManipulationConstants.SNI_NAME_TYPE_LENGTH + ManipulationConstants.SNI_NAME_LENGTH_LENGTH + correctHostname.length)) -
                // constant for other header bytes
                1000) /
                // divide by header + newHostname length
                (ManipulationConstants.SNI_NAME_TYPE_LENGTH + ManipulationConstants.SNI_NAME_LENGTH_LENGTH + incorrectHostname.length)
                    ) - 1 // always subtract one to have enough space for other manipulations such as symbol injections

        if (newEntryAmount < 1) {
            logger.error("Can not add more SNI entries in full extension")
            return
        }
        tlsConfig.addSniEntry(incorrectHostname, newEntryAmount / 2)
        tlsConfig.addSniEntry(correctHostname)
        tlsConfig.addSniEntry(incorrectHostname, newEntryAmount - (newEntryAmount / 2))
        tlsConfig.addSniEntry(correctHostname)

    }
}