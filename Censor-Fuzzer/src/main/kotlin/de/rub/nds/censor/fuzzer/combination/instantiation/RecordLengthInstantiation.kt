package de.rub.nds.censor.fuzzer.combination.instantiation

import de.rub.nds.censor.core.constants.ManipulationConstants.MAXIMUM_2_BYTE_FIELD_VALUE

enum class RecordLengthInstantiation(val modifier: Double) : Instantiation {
    CORRECT(1.0),
    HALF(0.5),
    DOUBLE(2.0),
    ZERO(0.0),
    MAX(MAXIMUM_2_BYTE_FIELD_VALUE.toDouble())
}