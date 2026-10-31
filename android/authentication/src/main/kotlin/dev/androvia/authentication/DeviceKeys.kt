package dev.androvia.authentication

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import dev.androvia.core.DeviceId
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

enum class KeySecurityLevel { STRONGBOX, TRUSTED_ENVIRONMENT, SOFTWARE, UNKNOWN }

data class DeviceIdentity(
    /** Hex SHA-256 of [publicKeySpki]. */
    val deviceId: String,
    /** X.509 SubjectPublicKeyInfo DER. The private key never leaves the Keystore. */
    val publicKeySpki: ByteArray,
    val securityLevel: KeySecurityLevel,
)

/** Abstraction so callers and tests do not depend on the Android Keystore directly. */
interface DeviceKeys {
    /** Returns the existing identity or creates it once. Stable across calls and process restarts. */
    fun identity(): DeviceIdentity

    /** Signs [data] with SHA256withECDSA using the device key. Output is ASN.1 DER. */
    fun sign(data: ByteArray): ByteArray
}

/**
 * EC P-256 key in Android Keystore (ADR 0003). Tries StrongBox first and falls back to the default
 * hardware/software implementation. The achieved security level is reported, never assumed.
 *
 * [alias] is injectable so tests can use a throwaway key. No user authentication is required per signature
 * (the runtime must answer challenges while locked); see ADR 0003 for that tradeoff.
 */
class AndroidKeystoreDeviceKeys(private val alias: String = DEFAULT_ALIAS) : DeviceKeys {
    private val lock = Any()

    override fun identity(): DeviceIdentity = synchronized(lock) {
        val ks = keyStore()
        if (!ks.containsAlias(alias)) generate()
        val cert = ks.getCertificate(alias) ?: error("Keystore entry has no certificate")
        val spki = cert.publicKey.encoded
        DeviceIdentity(DeviceId.fromPublicKeyDer(spki), spki, securityLevelOf(privateKey()))
    }

    override fun sign(data: ByteArray): ByteArray = synchronized(lock) {
        if (!keyStore().containsAlias(alias)) generate()
        Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey())
            update(data)
            sign()
        }
    }

    /** Test/reset helper. Deleting the key changes the device identity; the device must be re-paired. */
    fun deleteKey() = synchronized(lock) { keyStore().deleteEntry(alias) }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun privateKey(): PrivateKey =
        keyStore().getKey(alias, null) as? PrivateKey ?: error("Keystore entry is not a private key")

    private fun generate() {
        try {
            generate(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)
        } catch (e: ProviderException) {
            // Some devices throw a generic ProviderException when StrongBox is advertised but unusable.
            generate(strongBox = false)
        }
    }

    private fun generate(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun securityLevelOf(key: PrivateKey): KeySecurityLevel = try {
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeySecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeySecurityLevel.SOFTWARE
                else -> KeySecurityLevel.UNKNOWN
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) KeySecurityLevel.TRUSTED_ENVIRONMENT else KeySecurityLevel.SOFTWARE
        }
    } catch (e: Exception) {
        KeySecurityLevel.UNKNOWN
    }

    companion object {
        const val DEFAULT_ALIAS = "androvia.device.identity.v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }
}
