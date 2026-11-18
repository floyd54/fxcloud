package de.frischux.fxcloud

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.widget.TextView
import android.widget.Toast

/**
 * S1's whole UI: one label that runs the golden fingerprint through the
 * JNI boundary and shows the result. A committed vector from
 * tests/fixtures/fx-keys-vectors.json ("fingerprint: x25519 blob") -
 * the app must print exactly the committed fingerprint or the boundary
 * is broken (concepts/android.md, slice S1).
 *
 * Colors are set explicitly (dark panel, light text): the activity has
 * no theme, and a theme-less default rendered white-on-white on at
 * least one device. Anything that goes wrong before the label is up
 * surfaces as a Toast, never as a silent blank screen.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            val view = TextView(this)
            view.setBackgroundColor(Color.rgb(20, 22, 27))
            view.setTextColor(Color.rgb(230, 233, 238))
            view.textSize = 16f
            view.setPadding(64, 128, 64, 64)
            view.text = "fxcloud S1\n\nfingerprint via JNI ..."
            setContentView(view)

            val blob = hexToBytes(
                "019bd145b475294cc6b5d3543f2d18ab6a532a964cfdb7bb368295ba41ed1df543"
            )
            Thread {
                val result = try {
                    val fp = FxCore.fingerprint(blob)
                    val expect = "4cf65d73306f6745e84bb7fae2cd0c0e"
                    if (fp == expect) {
                        "fingerprint matches the golden vector\n$fp"
                    } else {
                        "MISMATCH: got $fp, want $expect"
                    }
                } catch (e: Throwable) {
                    "fingerprint failed: $e"
                }
                runOnUiThread { view.text = result }
            }.start()
        } catch (t: Throwable) {
            // Nothing on screen yet: say it where it can be seen.
            Toast.makeText(this, "fxcloud S1 failed to start: $t", Toast.LENGTH_LONG).show()
        }
    }
}
