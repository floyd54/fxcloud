package de.frischux.fxcloud

import java.io.File
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The markdown renderer is a port of the web's `mdToHtml`
 * (frontend/assets/app.js); the vectors are generated from the JS
 * itself by frontend/tests/gen-md-vectors.js, so a drift in either
 * implementation fails here - the app is another reader of the same
 * contract, not a new one.
 */
class MarkdownVectorsTest {
    private fun vectors(): JSONArray {
        val f = File("../../tests/fixtures/md-vectors.json")
        require(f.exists()) {
            "fixture not found at ${f.absolutePath} - run the tests from the app module"
        }
        return JSONArray(f.readText())
    }

    @Test
    fun markdownVectorsFromTheWebRenderer() {
        val arr = vectors()
        require(arr.length() > 0) { "fixture holds no vectors" }
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            val input = v.getString("input")
            val expected = v.getString("html")
            assertEquals(
                "vector $i: ${input.take(48).replace("\n", "\\n")}",
                expected,
                Markdown.toHtml(input)
            )
        }
    }
}
