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
        assertTrue("packed session is root+length+pkcs8", packed.size >= 36)
        val pkcs8Len =
            ((packed[32].toInt() and 0xff) shl 24) or
                ((packed[33].toInt() and 0xff) shl 16) or
                ((packed[34].toInt() and 0xff) shl 8) or
                (packed[35].toInt() and 0xff)
        assertEquals("packed layout", 36 + pkcs8Len, packed.size)
        val root = packed.copyOfRange(0, 32)
        val pkcs8 = packed.copyOfRange(36, packed.size)
        val expect = c.getJSONObject("expect")
        assertArrayEquals(
            "root key",
            b64(expect.getString("root_key_b64")),
            root
        )
        assertArrayEquals(
            "pkcs8",
            b64(expect.getString("private_key_pkcs8_b64")),
            pkcs8
        )
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
}
