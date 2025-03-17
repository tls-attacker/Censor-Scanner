/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tls.record

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.censor.core.util.RecordCreator

/**
 * Sets the maximum size for TLS records in the connection
 */
class RecordFragmentationSpecificSizeManipulation(val recordSize: Int) : TlsManipulation() {

    override fun afterRecordCreatorInit(recordCreator: RecordCreator) {
        recordCreator.initialMaxRecordSize = recordSize
    }

    override val name: String
        get() = "record_fragmentation(recordSize=$recordSize)"
}