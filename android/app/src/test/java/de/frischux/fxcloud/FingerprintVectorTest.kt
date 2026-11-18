package de.frischux.fxcloud

import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File

/**
 * The host-side golden vector through JNI (concepts/android.md A4): the
 * same fixture the browser, the Rust twin and the C ABI already answer -
 * a fingerprint that disagrees with the committed bytes fails here too.
 *
 * Loads the HOST build of libfxcloud.so (`cargo build -p fxjni`); on a
 * device the app loads the Android build through System.loadLibrary.
 */
class FingerprintVectorTest {
    private fun loadHostLibrary() {
        val candidates = listOf(
            "../../target/debug/libfxcloud.so",
            "../target/debug/libfxcloud.so",
            "target/debug/libfxcloud.so"
        )
        val lib = candidates.map(::File).firstOrNull(File::exists)
            ?: error(
                "host libfxcloud.so not found - run `cargo build -p fxjni` " +
                    "from the repository root first"
            )
        System.load(lib.absolutePath)
    }

    @Test
    fun goldenFingerprintThroughJni() {
        loadHostLibrary()
        // tests/fixtures/fx-keys-vectors.json - "fingerprint: x25519 blob".
        val blob = hexToBytes(
            "019bd145b475294cc6b5d3543f2d18ab6a532a964cfdb7bb368295ba41ed1df543"
        )
        assertEquals(
            "4cf65d73306f6745e84bb7fae2cd0c0e",
            FxCore.fingerprint(blob)
        )
    }

    @Test
    fun goldenFingerprintP256ThroughJni() {
        loadHostLibrary()
        // The second fixture row: the P-256 blob answers with its own
        // committed fingerprint - both suites travel the same boundary.
        val blob = hexToBytes(
            "0204ed8e2d8750ab2ed5c035064f5fd9f0290a5d0946c699ac66fe0e24c9bcd8b" +
                "58ff2a1cb3c32e68f52556612ec662e4c208a5c453d8855ffa60baafdb2a5f12a0e"
        )
        assertEquals(
            "d04f2b5cda81d79ad1a9b087f7746888",
            FxCore.fingerprint(blob)
        )
    }
}
