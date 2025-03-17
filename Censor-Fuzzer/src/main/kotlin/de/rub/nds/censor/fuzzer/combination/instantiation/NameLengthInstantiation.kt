package de.rub.nds.censor.fuzzer.combination.instantiation

import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE

enum class NameLengthInstantiation(val modifier: Double) : Instantiation {
    CORRECT(1.0),
    TOO_SHORT(0.5),
    KEEP_DEFAULT(1.0),
    TOO_LONG(2.0),
    ZERO(0.0),
    MAX(MAXIMUM_2_BYTE_FIELD_VALUE.toDouble())
}