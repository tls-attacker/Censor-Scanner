/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2017-2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.constants

import de.rub.nds.censor.core.network.IpAddress
import de.rub.nds.censor.core.network.Ipv4Address

/** Enum over known ip addresses  */
enum class Ip(
    val ipAddress: IpAddress
) {

    // in USA
    LOCALHOST(Ipv4Address("127.0.0.1")),

    // DNS
    GOOGLE_DNS_1(Ipv4Address("8.8.8.8")),
    GOOGLE_DNS_2(Ipv4Address("8.8.4.4")),

    CLOUDFLARE_DNS_1(Ipv4Address("1.1.1.1")),
    CLOUDFLARE_DNS_2(Ipv4Address("1.0.0.1")),

    QUAD9_1(Ipv4Address("9.9.9.9")),
    QUAD9_2(Ipv4Address("9.9.9.11")),

    ADGUARD_1(Ipv4Address("94.140.14.14")),
    ADGUARD_2(Ipv4Address("94.140.15.15")),
    ADGUARD_FAMILY_PROTECTED_1(Ipv4Address("94.140.14.15")),
    ADGUARD_FAMILY_PROTECTED_2(Ipv4Address("94.140.15.16")),
    ADGUARD_NON_FILTERING_1(Ipv4Address("94.140.14.140")),
    ADGUARD_NON_FILTERING_2(Ipv4Address("94.140.14.141")),

    CONTROL_UNIFILTERED_1(Ipv4Address("76.76.2.0")),
    CONTROL_UNIFILTERED_2(Ipv4Address("76.76.10.0")),
    CONTROL_MALWARE_1(Ipv4Address("76.76.2.1")),
    CONTROL_MALWARE_2(Ipv4Address("76.76.10.1")),
    CONTROL_ADS_1(Ipv4Address("76.76.2.2")),
    CONTROL_ADS_2(Ipv4Address("76.76.10.2")),
    CONTROL_SOCIAL_1(Ipv4Address("76.76.2.3")),
    CONTROL_SOCIAL_2(Ipv4Address("76.76.10.3")),
    CONTROL_FAMILY_1(Ipv4Address("76.76.2.4")),
    CONTROL_FAMILY_2(Ipv4Address("76.76.10.4")),
    CONTROL_UNCENSORED_1(Ipv4Address("76.76.2.5")),
    CONTROL_UNCENSORED_2(Ipv4Address("76.76.10.5"));


    val allDnsOverHTTPS: List<Ip>
        get() = listOf(
            GOOGLE_DNS_1,
            GOOGLE_DNS_2,
            CLOUDFLARE_DNS_1,
            CLOUDFLARE_DNS_2,
            QUAD9_1,
            QUAD9_2,
            ADGUARD_1,
            ADGUARD_2,
            ADGUARD_FAMILY_PROTECTED_1,
            ADGUARD_FAMILY_PROTECTED_2,
            ADGUARD_NON_FILTERING_1,
            ADGUARD_NON_FILTERING_2,
            CONTROL_UNIFILTERED_1,
            CONTROL_UNIFILTERED_2,
            CONTROL_MALWARE_1,
            CONTROL_MALWARE_2,
            CONTROL_ADS_1,
            CONTROL_ADS_2,
            CONTROL_SOCIAL_1,
            CONTROL_SOCIAL_2,
            CONTROL_FAMILY_1,
            CONTROL_FAMILY_2,
            CONTROL_UNCENSORED_1,
            CONTROL_UNCENSORED_2
        )

    val allDnsOverTLS: List<Ip>
        get() = listOf(
            GOOGLE_DNS_1,
            GOOGLE_DNS_2,
            CLOUDFLARE_DNS_1,
            CLOUDFLARE_DNS_2,
            QUAD9_1,
            QUAD9_2,
            ADGUARD_1,
            ADGUARD_2,
            ADGUARD_FAMILY_PROTECTED_1,
            ADGUARD_FAMILY_PROTECTED_2,
            ADGUARD_NON_FILTERING_1,
            ADGUARD_NON_FILTERING_2,
            CONTROL_UNIFILTERED_1,
            CONTROL_UNIFILTERED_2,
            CONTROL_MALWARE_1,
            CONTROL_MALWARE_2,
            CONTROL_ADS_1,
            CONTROL_ADS_2,
            CONTROL_SOCIAL_1,
            CONTROL_SOCIAL_2,
            CONTROL_FAMILY_1,
            CONTROL_FAMILY_2,
            CONTROL_UNCENSORED_1,
            CONTROL_UNCENSORED_2
        )

    override fun toString(): String {
        return name + "(" + ipAddress.address + ")"
    }
}