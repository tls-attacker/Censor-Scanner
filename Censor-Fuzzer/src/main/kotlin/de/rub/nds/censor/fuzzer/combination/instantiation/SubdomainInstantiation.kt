package de.rub.nds.censor.fuzzer.combination.instantiation

enum class SubdomainInstantiation(val subdomain: String) : Instantiation {
    NONE(""),
    WWW("www"),
    API("api")
}