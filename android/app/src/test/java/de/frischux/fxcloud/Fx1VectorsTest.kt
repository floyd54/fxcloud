package de.frischux.fxcloud

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Base64

/**
 * The FXE1 golden vectors through JNI (concepts/android.md S3a): the
 * read side is pinned by tests/fixtures/fx1-vectors.json - the same
 * committed bytes the browser and the Rust twin answer. The write side
 * takes a roundtrip instead: encryption draws a fresh nonce base, so
 * the JS crypto-roundtrip test is its pin, exactly as the fixture says.
 */
class Fx1VectorsTest {
    private fun fixture(): JSONObject {
        val f = File("../../tests/fixtures/fx1-vectors.json")
        require(f.exists()) {
            "fixture not found at ${f.absolutePath} - run the tests from the app module"
        }
        return JSONObject(f.readText())
    }

    @Test
    fun goldenDecryptThroughJni() {
        Native.load()
        val cases = fixture().getJSONArray("cases")
        var pinned = 0
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val key = hexToBytes(c.getString("key_hex"))
            val container = Base64.getDecoder().decode(c.getString("container_b64"))
            if (c.optBoolean("expect_error", false)) {
                try {
                    FxCore.decryptBytes(c.getLong("file_id"), key, container)
                    throw AssertionError("must fail: $name")
                } catch (e: RuntimeException) {
                    // Format problems answer FX_ERR_FORMAT, auth/id
                    // mismatches FX_ERR_CHUNK - both carry the code name.
                    assertTrue(
                        "code name for '$name': ${e.message}",
                        (e.message ?: "").contains("FX_ERR")
                    )
                }
            } else {
                val want = Base64.getDecoder().decode(c.getString("plain_b64"))
                assertArrayEquals(
                    name,
                    want,
                    FxCore.decryptBytes(c.getLong("file_id"), key, container)
                )
                pinned++
            }
        }
        assertTrue("vectors were checked", pinned > 0)
    }

    @Test
    fun roundtripAndIdBinding() {
        Native.load()
        val key =
            hexToBytes("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        val plain = "S3 roundtrip - äöü ✓".toByteArray(Charsets.UTF_8)
        val container = FxCore.encryptBytes(42, key, plain)
        assertArrayEquals(plain, FxCore.decryptBytes(42, key, container))
        // The AAD carries the file id: a row move must not open it.
        try {
            FxCore.decryptBytes(43, key, container)
            throw AssertionError("another file id must not open this container")
        } catch (e: RuntimeException) {
            assertTrue(
                "id binding error: ${e.message}",
                (e.message ?: "").contains("FX_ERR_CHUNK")
            )
        }
        // Wrong key fails the same way.
        val otherKey =
            hexToBytes("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
        try {
            FxCore.decryptBytes(42, otherKey, container)
            throw AssertionError("a wrong key must not open this container")
        } catch (e: RuntimeException) {
            assertTrue(
                "wrong key error: ${e.message}",
                (e.message ?: "").contains("FX_ERR_CHUNK")
            )
        }
    }
}
