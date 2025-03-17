package de.rub.nds.censor.fuzzer.config

import de.rub.nds.censor.fuzzer.constants.Strategies


enum class ExcludeStrategies(val strategiesToRemove: List<Strategies>) {
    NONE(listOf()),
    EXCLUDE_ALL_INVALID_ENTRY_STRATEGIES(
        listOf(
            Strategies.ADD_SUBDOMAIN, Strategies.INJECT_SYMBOL, Strategies.ASCII_PARITY_FLIP,
            Strategies.NAME_TYPE, Strategies.PAD_TO_MAXIMUM
        )
    )
}
