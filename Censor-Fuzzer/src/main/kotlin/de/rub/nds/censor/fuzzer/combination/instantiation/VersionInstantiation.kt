package de.rub.nds.censor.fuzzer.combination.instantiation

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion

enum class VersionInstantiation(val newVersion: ByteArray, val protocolVersion: ProtocolVersion) : Instantiation {
    DEFAULT(byteArrayOf(0x00, 0x00), ProtocolVersion.GREASE_00),
    TLS10(ProtocolVersion.TLS10.value, ProtocolVersion.TLS10),
    TLS11(ProtocolVersion.TLS11.value, ProtocolVersion.TLS11),
    TLS12(ProtocolVersion.TLS12.value, ProtocolVersion.TLS12),
    TLS13_DRAFT_28(ProtocolVersion.TLS13_DRAFT28.value, ProtocolVersion.TLS13_DRAFT28),
    TLS13(ProtocolVersion.TLS13.value, ProtocolVersion.TLS13),
    SSL3(ProtocolVersion.SSL3.value, ProtocolVersion.SSL3),
    SSL2(ProtocolVersion.SSL2.value, ProtocolVersion.SSL2),
    INVALID_SMALLER(byteArrayOf(0x00, 0x00), ProtocolVersion.SSL3),
    INVALID_BIGGER(byteArrayOf(0x20, 0x20), ProtocolVersion.GREASE_00)
}