package de.rub.nds.censor.core.connection.manipulation

/**
 * Models a manipulation of a basic connection such as a TLS 1.2 connection.
 *
 * <parameter> holds the type of the parameter that can be manipulated.
 */
abstract class Manipulation {

    /**
     * Every manipulation has a name
     */
    abstract val name: String

    override fun toString(): String {
        return "Manipulation(name=$name)"
    }
}