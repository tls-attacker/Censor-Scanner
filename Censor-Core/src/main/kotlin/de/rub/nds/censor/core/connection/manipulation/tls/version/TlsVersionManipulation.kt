/*
 * Censor-Scanner is able to perform large scale
 * analyses on censorship.
 *
 * Copyright 2022
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.censor.core.connection.manipulation.tls.version

import de.rub.nds.censor.core.connection.manipulation.tls.TlsManipulation
import de.rub.nds.tlsattacker.core.config.Config
import de.rub.nds.tlsattacker.core.constants.*

/**
 * Changes the TLS version used in the connection.
 */
class TlsVersionManipulation(val version: ProtocolVersion) : TlsManipulation() {
    /** Changes the config to the default values of a TLS 1.3 connection.  */
    override fun afterConfigInit(tlsConfig: Config) {
        when (version) {
            ProtocolVersion.TLS10 -> applyTls10(tlsConfig)
            ProtocolVersion.TLS11 -> applyTls11(tlsConfig)
            ProtocolVersion.TLS12 -> applyTls12(tlsConfig)
            ProtocolVersion.TLS13 -> applyTls13(tlsConfig)
            else -> throw UnsupportedOperationException("Version $version not supported")
        }
    }

    private fun applyTls10(tlsConfig: Config) {
        tlsConfig.supportedVersions = listOf(version)
        tlsConfig.highestProtocolVersion = version
        tlsConfig.defaultSelectedProtocolVersion = version
        tlsConfig.defaultSelectedCompressionMethod = CompressionMethod.NULL
        tlsConfig.isEnforceSettings = true
    }

    private fun applyTls11(tlsConfig: Config) {
        tlsConfig.supportedVersions = listOf(version)
        tlsConfig.highestProtocolVersion = version
        tlsConfig.defaultSelectedProtocolVersion = version
        tlsConfig.defaultSelectedCompressionMethod = CompressionMethod.NULL
        tlsConfig.isEnforceSettings = true
    }

    private fun applyTls12(tlsConfig: Config) {
        tlsConfig.supportedVersions = listOf(version)
        tlsConfig.highestProtocolVersion = version
        tlsConfig.defaultSelectedProtocolVersion = version
        tlsConfig.defaultSelectedCompressionMethod = CompressionMethod.NULL
        tlsConfig.isEnforceSettings = true
    }

    private fun applyTls13(tlsConfig: Config) {
        tlsConfig.highestProtocolVersion = ProtocolVersion.TLS13
        tlsConfig.supportedVersions = listOf(ProtocolVersion.TLS13)
        val clientSupportedCipherSuites = ArrayList<CipherSuite>()
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256)
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384)
        val serverSupportedCipherSuites = ArrayList<CipherSuite>()
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256)
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384)
        tlsConfig.defaultClientSupportedCipherSuites = clientSupportedCipherSuites
        tlsConfig.defaultServerSupportedCipherSuites = serverSupportedCipherSuites
        val defaultClientNamedGroups = ArrayList<NamedGroup>()
        defaultClientNamedGroups.add(NamedGroup.ECDH_X25519)
        tlsConfig.defaultClientNamedGroups = defaultClientNamedGroups
        val defaultServerNamedGroups = ArrayList<NamedGroup>()
        defaultServerNamedGroups.add(NamedGroup.ECDH_X25519)
        tlsConfig.defaultServerNamedGroups = defaultServerNamedGroups
        val clientSignatureAndHashAlgorithms = ArrayList<SignatureAndHashAlgorithm>()
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256)
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384)
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512)
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256)
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384)
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512)
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256)
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384)
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512)
        tlsConfig.defaultClientSupportedSignatureAndHashAlgorithms = clientSignatureAndHashAlgorithms
        val serverSignatureAndHashAlgorithms = ArrayList<SignatureAndHashAlgorithm>()
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256)
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384)
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512)
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256)
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384)
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512)
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256)
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384)
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512)
        tlsConfig.defaultServerSupportedSignatureAndHashAlgorithms = serverSignatureAndHashAlgorithms
        tlsConfig.defaultSelectedNamedGroup = NamedGroup.ECDH_X25519
        tlsConfig.defaultSelectedCipherSuite = CipherSuite.TLS_AES_128_GCM_SHA256
        tlsConfig.defaultClientKeyShareNamedGroups = listOf(NamedGroup.ECDH_X25519)
        tlsConfig.isAddECPointFormatExtension = false
        tlsConfig.isAddEllipticCurveExtension = true
        tlsConfig.isAddSignatureAndHashAlgorithmsExtension = true
        tlsConfig.isAddSupportedVersionsExtension = true
        tlsConfig.isAddKeyShareExtension = true
        tlsConfig.isAddRenegotiationInfoExtension = false
    }

    override val name: String
        get() = "TlsVersion($version)"
}