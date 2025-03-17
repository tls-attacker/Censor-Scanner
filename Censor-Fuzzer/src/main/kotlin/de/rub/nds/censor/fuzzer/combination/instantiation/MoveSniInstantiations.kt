package de.rub.nds.censor.fuzzer.combination.instantiation

enum class MoveSniInstantiations(val position: Int) : Instantiation {
    CORRECT(-99), // no replacement
    FIRST(0),
    LAST(-1)
}