package de.rub.nds.censor.fuzzer.constants

object CensorshipValues {
    // 7 minutes
    const val CHINA_RESIDUAL_CENSORSHIP_TIME: Long = 420000
    const val CHINA_PORT_RANGE_START = 10000
    const val CHINA_PORT_RANGE_END = 10999
    const val DECISION_BARRIER = 0.666666666666
    const val MAX_TRIES = 20
    const val MAX_TIMEOUT_TRIES = 30
    const val INITIAL_TRIES = 3
}