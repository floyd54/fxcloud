package de.frischux.fxcloud

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.widget.TextView
import android.widget.Toast

/**
 * S1's UI - and the diagnostic bring-up build (three layers, so a blank
 * screen can never again be ambiguous):
 *
 *  1. the window: Theme.Fxcloud paints the window green before any code
 *  2. the title: setTitle right after super.onCreate - if the action bar
 *     says "S1-ONCREATE-RAN", this method started
 *  3. the content: an inflated layout (the other setContentView path)
 *     with static colors; the fingerprint result lands in R.id.result
 *
 * Anything that throws before the content is up shows a Toast AND an
 * alert dialog - never a silent blank.
 */
class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Layer2 probe: visible on the action bar before anything else.
        setTitle("S1-ONCREATE-RAN")
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
