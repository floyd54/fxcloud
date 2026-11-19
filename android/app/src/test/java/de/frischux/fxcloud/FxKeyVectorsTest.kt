package de.frischux.fxcloud

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * The golden key vectors through JNI (concepts/android.md A4): the same
 * fixture the browser, the Rust twin and the C ABI already answer
 * (tests/fixtures/fx-keys-vectors.json, written by
 * frontend/tests/gen-key-vectors.js). A result that disagrees with the
 * committed bytes fails here too - the app is another reader of the
 * same format, not a new one.
 */
class FxKeyVectorsTest {
    private fun fixture(): JSONObject {
        val f = File("../../tests/fixtures/fx-keys-vectors.json")
        require(f.exists()) {
            "fixture not found at ${f.absolutePath} - run the tests from the app module"
        }
        return JSONObject(f.readText())
    }

    private fun caseOf(kind: String): JSONObject {
        val arr = fixture().getJSONArray("cases")
        for (i in 0 until arr.length()) {
            val c = arr.getJSONObject(i)
            if (c.getString("kind") == kind) return c
        }
        error("no '$kind' case in the fixture")
    }

    private fun b64(s: String): ByteArray = Base64.getDecoder().decode(s)

    @Test
    fun goldenChildUnwrapThroughJni() {
        Native.load()
        val c = caseOf("child")
        val got = FxCore.unwrapChild(
            hexToBytes(c.getString("parent_key_hex")),
            c.getLong("child_id"),
            c.getString("wrapped_child_b64")
        )
        assertArrayEquals(hexToBytes(c.getString("child_key_hex")), got)
    }

    @Test
    fun goldenUnlockThroughJni() {
        Native.load()
        val c = caseOf("unlock")
        val packed = FxCore.unlock(c.getJSONObject("keys").toString(), c.getString("passphrase"))
        assertPackedSession(packed, c.getJSONObject("expect"))
    }

    @Test
    fun wrongPassphraseIsAnExceptionNotGarbage() {
        Native.load()
        val c = caseOf("unlock")
        try {
            FxCore.unlock(c.getJSONObject("keys").toString(), c.getString("passphrase") + "x")
            throw AssertionError("unlock with a wrong passphrase must throw")
        } catch (e: RuntimeException) {
            // The unified unwrap failure travels as the exception text.
            assertTrue(
                "message names the failure: ${e.message}",
                (e.message ?: "").contains("FX_ERR_UNWRAP")
            )
        }
    }

    private fun casesOf(kind: String): List<JSONObject> {
        val arr = fixture().getJSONArray("cases")
        val out = ArrayList<JSONObject>()
        for (i in 0 until arr.length()) {
            val c = arr.getJSONObject(i)
            if (c.getString("kind") == kind) out.add(c)
        }
        require(out.isNotEmpty()) { "no '$kind' case in the fixture" }
        return out
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { String.format("%02x", it.toInt() and 0xff) }

    /** The packed session assertions the unlock test also makes. */
    /** The packed layout since S4b: root(32) || u32 pkcs8Len || pkcs8
     *  || u32 arkLen || ark - every field byte-compared against the
     *  fixture; the ark tail is what the device blob stores (S4b). */
    private fun assertPackedSession(packed: ByteArray, expect: JSONObject) {
        assertTrue("packed session is root+lengths+tails", packed.size >= 40)
        val pkcs8Len = u32(packed, 32)
        val arkLen = u32(packed, 36 + pkcs8Len)
        assertEquals("packed layout", 40 + pkcs8Len + arkLen, packed.size)
        assertArrayEquals(
            "root key",
            b64(expect.getString("root_key_b64")),
            packed.copyOfRange(0, 32)
        )
        assertArrayEquals(
            "pkcs8",
            b64(expect.getString("private_key_pkcs8_b64")),
            packed.copyOfRange(36, 36 + pkcs8Len)
        )
        val arkExpect = expect.optString("ark_b64")
        if (arkExpect.isNotEmpty()) {
            assertArrayEquals(
                "ark",
                b64(arkExpect),
                packed.copyOfRange(40 + pkcs8Len, packed.size)
            )
        }
    }

    private fun u32(p: ByteArray, at: Int): Int =
        ((p[at].toInt() and 0xff) shl 24) or
            ((p[at + 1].toInt() and 0xff) shl 16) or
            ((p[at + 2].toInt() and 0xff) shl 8) or
            (p[at + 3].toInt() and 0xff)

    @Test
    fun goldenRecoveryOpenThroughJni() {
        Native.load()
        val c = casesOf("recovery_open").first { !it.optBoolean("expect_error", false) }
        val recoveryHex = hex(b64(c.getString("recovery_key_b64")))
        val packed = FxCore.unlockWithRecovery(c.getJSONObject("keys").toString(), recoveryHex)
        assertPackedSession(packed, c.getJSONObject("expect"))
    }

    @Test
    fun wrongRecoveryKeyIsAnException() {
        Native.load()
        val c = casesOf("recovery_open").first { it.optBoolean("expect_error", false) }
        val recoveryHex = hex(b64(c.getString("recovery_key_b64")))
        try {
            FxCore.unlockWithRecovery(c.getJSONObject("keys").toString(), recoveryHex)
            throw AssertionError("a wrong recovery key must throw")
        } catch (e: RuntimeException) {
            assertTrue(
                "message names a failure: ${e.message}",
                (e.message ?: "").contains("FX_ERR")
            )
        }
    }

    @Test
    fun goldenEciesOpenThroughJni() {
        Native.load()
        val c = casesOf("ecies_open").first { !it.optBoolean("expect_error", false) }
        val aad = c.getJSONObject("aad")
        val got = FxCore.eciesOpen(
            b64(c.getString("envelope_b64")),
            b64(c.getString("recipient_pkcs8_b64")),
            aad.getLong("source_id"),
            aad.getString("grantee")
        )
        assertArrayEquals(b64(c.getString("plaintext_b64")), got)
    }

    @Test
    fun eciesSealOpensAgainAndBindsTheAad() {
        Native.load()
        val c = casesOf("ecies_open").first { !it.optBoolean("expect_error", false) }
        val aad = c.getJSONObject("aad")
        val sourceId = aad.getLong("source_id")
        val grantee = aad.getString("grantee")
        val plain = "sealed on the phone".toByteArray(Charsets.UTF_8)
        // The envelope carries an ephemeral key - pin the roundtrip, not
        // the bytes (the fixture pins the deterministic error side).
        val envelope = FxCore.eciesSeal(b64(c.getString("recipient_public_b64")), plain, sourceId, grantee)
        assertArrayEquals(plain, FxCore.eciesOpen(envelope, b64(c.getString("recipient_pkcs8_b64")), sourceId, grantee))
        // Another share's id must not open it (the AAD binds both).
        try {
            FxCore.eciesOpen(envelope, b64(c.getString("recipient_pkcs8_b64")), sourceId + 1, grantee)
            throw AssertionError("a foreign source id must not open the envelope")
        } catch (e: RuntimeException) {
            assertTrue(
                "unified unwrap message: ${e.message}",
                (e.message ?: "").contains("FX_ERR_UNWRAP")
            )
        }
    }

    @Test
    fun wrapChildRoundtripsThroughJni() {
        Native.load()
        val c = caseOf("child")
        val parent = hexToBytes(c.getString("parent_key_hex"))
        val id = c.getLong("child_id")
        val childKey = hexToBytes(c.getString("child_key_hex"))
        // wrap draws a fresh nonce (like the JS twin), so the pin is
        // the roundtrip through both JNI directions; the fixture pins
        // the read side byte-for-byte in goldenChildUnwrapThroughJni.
        val wrapped = FxCore.wrapChild(parent, id, childKey)
        assertArrayEquals(
            childKey,
            FxCore.unwrapChild(
                parent, id, java.util.Base64.getEncoder().encodeToString(wrapped)
            )
        )
    }

    @Test
    fun wrapUnwrapWithShareAadRoundtrip() {
        Native.load()
        // N4's shape: a mount label under the node's key with the share
        // AAD - url-safe on the wire like the web's b64url.
        val ecies = casesOf("ecies_open").first { !it.optBoolean("expect_error", false) }
        val aadObj = ecies.getJSONObject("aad")
        val sourceId = aadObj.getLong("source_id")
        val grantee = aadObj.getString("grantee")
        val key = hexToBytes(caseOf("child").getString("parent_key_hex"))
        val aad = FxCore.shareEnvelopeAad(sourceId, grantee)
        val label = "Geteilter Ordner".toByteArray(Charsets.UTF_8)
        val wrapped = FxCore.wrap(key, label, aad)
        val blob = java.util.Base64.getUrlEncoder().encodeToString(wrapped)
        assertArrayEquals(label, FxCore.unwrap(key, blob, aad))
        // The AAD binds share id and grantee: another share's id fails.
        try {
            FxCore.unwrap(key, blob, FxCore.shareEnvelopeAad(sourceId + 1, grantee))
            throw AssertionError("another share id must not open this label")
        } catch (e: RuntimeException) {
            assertTrue(
                "unified unwrap message: ${e.message}",
                (e.message ?: "").contains("FX_ERR_UNWRAP")
            )
        }
    }

    @Test
    fun goldenSessionFromArkThroughJni() {
        Native.load()
        val c = casesOf("session").first { !it.optBoolean("expect_error", false) }
        val ark = b64(c.getString("ark_b64"))
        val packed = FxCore.sessionFromArk(c.getJSONObject("keys").toString(), ark)
        assertPackedSession(packed, c.getJSONObject("expect"))
        // The ark rides back unchanged - the device blob's roundtrip.
        val pkcs8Len = u32(packed, 32)
        assertArrayEquals(
            "ark tail",
            ark,
            packed.copyOfRange(40 + pkcs8Len, packed.size)
        )
    }

    @Test
    fun foreignArkIsAnException() {
        Native.load()
        val c = casesOf("session").first { !it.optBoolean("expect_error", false) }
        val ark = b64(c.getString("ark_b64"))
        ark[0] = (ark[0].toInt() xor 0xff).toByte()
        try {
            FxCore.sessionFromArk(c.getJSONObject("keys").toString(), ark)
            throw AssertionError("a foreign ark must not open a session")
        } catch (e: RuntimeException) {
            assertTrue(
                "code name: ${e.message}",
                (e.message ?: "").contains("FX_ERR")
            )
        }
    }
}
