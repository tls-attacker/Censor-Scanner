package de.rub.nds.censor.core.exception

import de.rub.nds.censor.core.constants.ConnectionReturn
import java.security.InvalidParameterException

class NotConnectableException : Exception {

    val reason: ConnectionReturn

    constructor(reason: ConnectionReturn) : super() {
        this.reason = reason
        validateReason()
    }

    constructor(reason: ConnectionReturn, message: String) : super(message) {
        this.reason = reason
        validateReason()
    }

    constructor(reason: ConnectionReturn, message: String, cause: Throwable) : super(message, cause) {
        this.reason = reason
        validateReason()
    }

    constructor(reason: ConnectionReturn, cause: Throwable) : super(cause) {
        this.reason = reason
        validateReason()
    }

    private fun validateReason() {
        if (reason == ConnectionReturn.WORKING) {
            throw InvalidParameterException("Reason for not connectable cannot be WORKING")
        }
    }

    override fun toString(): String {
        return reason.toString() + ": " + super.toString()
    }

}