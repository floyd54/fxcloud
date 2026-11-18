package de.frischux.fxcloud

/**
 * The JNI surface of `libfxcloud.so` (concepts/android.md A3): thin,
 * bytes-in bytes-out, errors as exceptions - the crypto itself stays in
 * Rust, behind the same C ABI the vectors pin.
 *
 * S1 exposes exactly one call, the smoke of the whole boundary: a
 * published-key blob in, its display fingerprint (32 hex characters)
 * out. Later slices add unlock, decrypt, seal - each one a translation,
 * never a re-implementation.
 */
object FxCore {
    init {
        try {
            System.loadLibrary("fxcloud")
        } catch (_: UnsatisfiedLinkError) {
            // Host-side unit tests load the .so by absolute path instead
            // (see FingerprintVectorTest); on a device this cannot fail
            // silently - the first call would throw.
        }
    }

    external fun fingerprint(blob: ByteArray): String

    /**
     * Unlock with the storage passphrase (S2): the account material as
     * /api/keys/me sends it, packed as root_key(32) || u32be(pkcs8_len)
     * || pkcs8 - Argon2id and the ARK chain run in Rust.
     */
    external fun unlock(keysJson: String, passphrase: String): ByteArray

    /**
     * Unwrap a child record or a wrapped name under its parent key (S2):
     * the raw value out, or a RuntimeException when it does not open -
     * the caller distinguishes "not mine" by catching, like the JS
     * twin's null. Blobs may be standard or URL-safe base64.
     */
    external fun unwrapChild(parentKey: ByteArray, childId: Long, wrapped: String): ByteArray
}

/** Hex string -> bytes; the golden fixtures speak hex and base64. */
fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "odd hex length" }
    return ByteArray(hex.length / 2) { i ->
        ((hex[i * 2].digitToInt(16) shl 4) or hex[i * 2 + 1].digitToInt(16)).toByte()
    }
}
