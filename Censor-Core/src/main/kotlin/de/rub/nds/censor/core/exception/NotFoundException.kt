package de.rub.nds.censor.core.exception

/**
 * Exception when WorkflowTraceUtil does not find sth. like a SNI extension
 */
class NotFoundException(
    override val message: String? = null,
    override val cause: Throwable? = null,
    enableSuppression: Boolean = false,
    writableStackTrace: Boolean = false
) : Exception(message, cause, enableSuppression, writableStackTrace)