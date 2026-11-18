package de.frischux.fxcloud

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.widget.TextView
import android.widget.Toast

/**
 * S1's whole UI: a label that runs the golden fingerprint through the
 * JNI boundary and shows the result. A committed vector from
 * tests/fixtures/fx-keys-vectors.json ("fingerprint: x25519 blob") -
 * the app must print exactly the committed fingerprint or the boundary
 * is broken (concepts/android.md, slice S1).
 *
 * Shapes here are the ones proven on the first real device: an inflated
 * layout with explicit colors (two earlier builds rendered blank), and
 * everything that throws before the content is up surfaces as a Toast
 * AND an alert dialog - never a silent white screen.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_main)
            val result = findViewById<TextView>(R.id.result)

            val blob = hexToBytes(
                "019bd145b475294cc6b5d3543f2d18ab6a532a964cfdb7bb368295ba41ed1df543"
            )
            Thread {
                val text = try {
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
                runOnUiThread { result.text = text }
            }.start()
        } catch (t: Throwable) {
            val msg = "fxcloud S1 failed to start: $t"
            Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
            AlertDialog.Builder(this).setMessage(msg).setPositiveButton("OK", null).show()
        }
    }
}
