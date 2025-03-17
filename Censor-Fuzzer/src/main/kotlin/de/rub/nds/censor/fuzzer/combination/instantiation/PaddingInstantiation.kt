package de.rub.nds.censor.fuzzer.combination.instantiation

import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_MAX_RECORD_SIZE_CORRECT
import de.rub.nds.censor.core.constants.ManipulationConstants.TLS_MAX_RECORD_SIZE_POSSIBLE

enum class PaddingInstantiation(val padToSize: Int) : Instantiation {
    NONE(0),
    PADDING_EXT_MAX_RECORD(TLS_MAX_RECORD_SIZE_CORRECT),
    PADDING_EXT_MAX_MESSAGE(TLS_MAX_RECORD_SIZE_POSSIBLE),
    CIPHER_SUITES_MAX_RECORD(TLS_MAX_RECORD_SIZE_CORRECT),
    CIPHER_SUITES_MAX_MESSAGE(TLS_MAX_RECORD_SIZE_POSSIBLE)
}