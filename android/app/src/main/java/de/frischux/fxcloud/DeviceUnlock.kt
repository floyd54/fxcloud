package de.frischux.fxcloud

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The hardware half of S4b: a random device key that never leaves the
 * Android Keystore, encrypting what the stored blob carries - the web's
 * localStorage device key (ENCRYPTION.md 5.7) with the key itself in
 * secure hardware, the "hardware-backed upgrade" of A5.
 *
 * Everything here is best effort, like the web's: storage or Keystore
 * that refuses simply means no auto-unlock next time, and the passphrase
 * pane stays the fallback.
 */
object DeviceUnlock {
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val IV_LEN = 12

    private fun alias(userId: Long) = "fxcloud.device.$userId"

    private fun storeKey(userId: Long): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = ks.getEntry(alias(userId), null)
        if (existing is KeyStore.SecretKeyEntry) return existing.secretKey
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(
                alias(userId),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build()
        )
        return gen.generateKey()
    }

    /** Encrypt the device key for prefs: base64(iv || ct), or null. */
    fun seal(userId: Long, deviceKey: ByteArray): String? = try {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, storeKey(userId))
        Base64.getEncoder().encodeToString(cipher.iv + cipher.doFinal(deviceKey))
    } catch (e: Throwable) {
        null
    }

    /** The device key back; null on anything that smells of tamper. */
    fun open(userId: Long, stored: String): ByteArray? = try {
        val bytes = Base64.getDecoder().decode(stored)
        require(bytes.size > IV_LEN) { "device key blob too short" }
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(
            Cipher.DECRYPT_MODE,
            storeKey(userId),
            GCMParameterSpec(128, bytes, 0, IV_LEN)
        )
        cipher.doFinal(bytes, IV_LEN, bytes.size - IV_LEN)
    } catch (e: Throwable) {
        null
    }
}

/**
 * The biometric twin of [DeviceUnlock]: the same blob layout, but
 * the Keystore key demands a strong biometric for every use - the
 * fingerprint gate of the passphrase pane (concepts/android.md,
 * fingerprint unlock). The caller prompts first (a plain
 * BiometricPrompt marks the authentication the key asks for), this
 * side only refuses crypto that ran without it.
 */
object BioUnlock {
    private const val TRANSFORM = "AES/GCM/NoPadding"
    private const val IV_LEN = 12
    private const val AUTH_SECONDS = 30

    private fun alias(userId: Long) = "fxcloud.bio.$userId"

    private fun storeKey(userId: Long): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = ks.getEntry(alias(userId), null)
        if (existing is KeyStore.SecretKeyEntry) return existing.secretKey
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(
            alias(userId),
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
        if (Build.VERSION.SDK_INT >= 30) {
            // Every use, strong biometric only: the platform marks the
            // user authenticated by the prompt that precedes each call.
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            // Per-use keys need API 30; a short window is the old
            // way to say the same thing - the prompt runs right
            // before the crypto either way.
            spec.setUserAuthenticationValidityDurationSeconds(AUTH_SECONDS)
        }
        gen.init(spec.build())
        return gen.generateKey()
    }

    /** Encrypt the device key for prefs: base64(iv || ct), or null. */
    fun seal(userId: Long, deviceKey: ByteArray): String? = try {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, storeKey(userId))
        Base64.getEncoder().encodeToString(cipher.iv + cipher.doFinal(deviceKey))
    } catch (e: Throwable) {
        null
    }

    /** The device key back; null without fresh authentication. */
    fun open(userId: Long, stored: String): ByteArray? = try {
        val bytes = Base64.getDecoder().decode(stored)
        require(bytes.size > IV_LEN) { "device key blob too short" }
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(
            Cipher.DECRYPT_MODE,
            storeKey(userId),
            GCMParameterSpec(128, bytes, 0, IV_LEN)
        )
        cipher.doFinal(bytes, IV_LEN, bytes.size - IV_LEN)
    } catch (e: Throwable) {
        null
    }
}
