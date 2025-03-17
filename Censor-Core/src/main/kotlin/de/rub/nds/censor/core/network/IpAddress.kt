/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2017-2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.network

import kotlinx.serialization.Serializable

/**
 * Holds an IP address. An object must only be constructable if the given address is valid. This
 * allows for easier ... easier what?
 */
@Serializable
sealed class IpAddress {

    abstract val address: String

    /**
     * Returns true, if the given ip address is valid
     * Must be a static check that does not use fields of its implementing class.
     * Otherwise, this function might be missing fields from a half-initialized object
     */
    protected abstract fun isValid(address: String): Boolean

    abstract fun isLocalhost(): Boolean

    override fun toString(): String {
        return address
    }
}