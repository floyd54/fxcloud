/**
 * The web's mini markdown renderer (`mdToHtml` in
 * frontend/assets/app.js), ported line for line: HTML-escape first,
 * code spans are lifted out before every other inline rule, link and
 * image targets are restricted to http(s)/relative/# so a note can
 * never run script in this origin, then the block walk (fence, blank,
 * heading, hr, quote, lists, paragraph).
 *
 * The vectors in tests/fixtures/md-vectors.json are generated from
 * the JS itself (frontend/tests/gen-md-vectors.js): the two
 * renderers cannot drift apart without the JVM test failing.
 */
object Markdown {

    fun toHtml(src: String): String {
        val esc = { s: String ->
            s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
        }
        val safeUrl = { u: String ->
            val t = u.trim()
            if (Regex("^(https?://|/|#)", RegexOption.IGNORE_CASE).containsMatchIn(t)) t else "#"
        }

        fun inline(input: String): String {
            var out = esc(input)
            // Code spans first: their content must survive every other rule.
            val codes = mutableListOf<String>()
            out = Regex("`([^`]+)`").replace(out) { m ->
                codes.add(m.groupValues[1])
                "\uE000${codes.size - 1}\uE000"
            }
            out = Regex("!\\[([^\\]]*)\\]\\(([^)\\s]+)\\)").replace(out) { m ->
                val target = safeUrl(m.groupValues[2])
                if (target == "#") m.groupValues[1]
                else "<img src=\"$target\" alt=\"${m.groupValues[1]}\">"
            }
            out = Regex("\\[([^\\]]+)\\]\\(([^)\\s]+)\\)").replace(out) { m ->
                "<a href=\"${safeUrl(m.groupValues[2])}\" " +
                    "target=\"_blank\" rel=\"noopener noreferrer\">" +
                    "${m.groupValues[1]}</a>"
            }
            out = Regex("\\*\\*([^*]+)\\*\\*").replace(out) {
                "<strong>${it.groupValues[1]}</strong>"
            }
            out = Regex("\\*([^*]+)\\*").replace(out) {
                "<em>${it.groupValues[1]}</em>"
            }
            out = Regex("~~([^~]+)~~").replace(out) {
                "<del>${it.groupValues[1]}</del>"
            }
            return Regex("\uE000(\\d+)\uE000").replace(out) { m ->
                "<code>${codes[m.groupValues[1].toInt()]}</code>"
            }
        }

        val lines = src.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        val html = StringBuilder()
        val para = mutableListOf<String>()
        var listType: String? = null // "ul" | "ol" while a list is open
        val quote = mutableListOf<String>()
        var fence: MutableList<String>? = null // an open ``` block

        fun closePara() {
            if (para.isNotEmpty()) {
                html.append("<p>").append(para.joinToString("<br>")).append("</p>")
                para.clear()
            }
        }
        fun closeList() {
            listType?.let {
                html.append("</").append(it).append(">")
                listType = null
            }
        }
        fun closeQuote() {
            if (quote.isNotEmpty()) {
                html.append("<blockquote>").append(quote.joinToString("<br>"))
                    .append("</blockquote>")
                quote.clear()
            }
        }

        val fenceMark = Regex("^\\s*```")
        for (raw in lines) {
            if (fence != null) {
                if (fenceMark.containsMatchIn(raw)) {
                    html.append("<pre><code>")
                        .append(esc(fence.joinToString("\n"))).append("</code></pre>")
                    fence = null
                } else {
                    fence.add(raw)
                }
                continue
            }
            if (fenceMark.containsMatchIn(raw)) {
                closePara(); closeList(); closeQuote()
                fence = mutableListOf()
                continue
            }
            if (raw.isBlank()) {
                closePara(); closeList(); closeQuote()
                continue
            }
            val heading = Regex("^(#{1,6})\\s+(.*)$").find(raw)
            if (heading != null) {
                closePara(); closeList(); closeQuote()
                val level = heading.groupValues[1].length
                html.append("<h").append(level).append(">")
                    .append(inline(heading.groupValues[2]))
                    .append("</h").append(level).append(">")
                continue
            }
            if (Regex("^\\s*(-{3,}|\\*{3,}|_{3,})\\s*$").matches(raw)) {
                closePara(); closeList(); closeQuote()
                html.append("<hr>")
                continue
            }
            val quoted = Regex("^>\\s?(.*)$").find(raw)
            if (quoted != null) {
                closePara(); closeList()
                quote.add(inline(quoted.groupValues[1]))
                continue
            }
            val ulItem = Regex("^\\s*[-*+]\\s+(.*)$").find(raw)
            val olItem = Regex("^\\s*\\d+\\.\\s+(.*)$").find(raw)
            if (ulItem != null || olItem != null) {
                closePara(); closeQuote()
                val want = if (ulItem != null) "ul" else "ol"
                if (listType != want) {
                    closeList()
                    html.append("<").append(want).append(">")
                    listType = want
                }
                val item = (ulItem ?: olItem)!!.groupValues[1]
                html.append("<li>").append(inline(item)).append("</li>")
                continue
            }
            closeList(); closeQuote()
            para.add(inline(raw))
        }
        fence?.let {
            html.append("<pre><code>").append(esc(it.joinToString("\n")))
                .append("</code></pre>")
        }
        closePara(); closeList(); closeQuote()
        return html.toString()
    }
}
