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

    /**
     * Wrap a value under a parent key bound to the child id (S3): the
     * content-key record of an upload and the id-bound name blob (N3)
     * are both this call - the raw wrap out, the caller encodes it.
     */
    external fun wrapChild(parentKey: ByteArray, childId: Long, value: ByteArray): ByteArray

    /**
     * Wrap with a caller-supplied AAD (S3d/S4): a mount's display label
     * uses the share AAD (N4), not a child AAD.
     */
    external fun wrap(key: ByteArray, value: ByteArray, aad: ByteArray): ByteArray

    /**
     * Unwrap with a caller-supplied AAD (S3d/S4); wrong key, tampering
     * and a foreign AAD all arrive as FX_ERR_UNWRAP. The blob may be
     * standard or URL-safe base64.
     */
    external fun unwrap(key: ByteArray, blob: String, aad: ByteArray): ByteArray

    /**
     * FXE1-encrypt a file body (S3): file id +32-byte content key in,
     * the container out - bound to the id, a row move fails decryption.
     */
    external fun encryptBytes(fileId: Long, key: ByteArray, plain: ByteArray): ByteArray

    /**
     * Decrypt an FXE1 container (S3); wrong key, wrong id, tampering
     * and non-containers arrive as FX_ERR_* exceptions.
     */
    external fun decryptBytes(fileId: Long, key: ByteArray, container: ByteArray): ByteArray

    /**
     * Open the account with the32-byte recovery key (S3): hex in, the
     * same packed session unlock returns. Grouping spaces/dashes in the
     * typed key are ignored.
     */
    external fun unlockWithRecovery(keysJson: String, recoveryKeyHex: String): ByteArray

    /**
     * The AAD binding a share envelope to source id + grantee (5.5) -
     * an envelope from another share or user cannot open.
     */
    external fun shareEnvelopeAad(sourceId: Long, grantee: String): ByteArray

    /**
     * Open an envelope sealed to me with my pkcs8 (S3/S4): the share
     * record out; wrong recipient, tampering or a foreign AAD throw the
     * unified FX_ERR_UNWRAP.
     */
    external fun eciesOpen(
        envelope: ByteArray,
        recipientPkcs8: ByteArray,
        sourceId: Long,
        grantee: String
    ): ByteArray

    /**
     * Seal a share record to a recipient's public key (S4's primitive,
     * landed in S3): ephemeral key inside, bytes fresh every call.
     */
    external fun eciesSeal(
        recipientPublic: ByteArray,
        plain: ByteArray,
        sourceId: Long,
        grantee: String
    ): ByteArray
}

/** Hex string -> bytes; the golden fixtures speak hex and base64. */
fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "odd hex length" }
    return ByteArray(hex.length / 2) { i ->
        ((hex[i * 2].digitToInt(16) shl 4) or hex[i * 2 + 1].digitToInt(16)).toByte()
    }
}
