package de.frischux.fxcloud

import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

/**
 * The REST client: the same endpoints and the same `fxcloud_session`
 * cookie the browser uses (concepts/android.md A6 - the server cannot
 * tell the difference and needs no change).
 *
 * Synchronous by design: every call runs on a background thread the
 * screens provide, so the skeleton carries no coroutine dependency.
 */
class ApiClient(var baseUrl: String) {

    /** The session token, kept exactly like the browser keeps its cookie. */
    var sessionCookie: String? = null

    data class Reply(val code: Int, val body: String, val setCookie: String?)

    companion object {
        /** Accept a bare host like a browser's address bar: anything
         *  without a scheme becomes https (a scheme-less value would
         *  otherwise become a file: URL and blow up on the connection). */
        fun normalizeBaseUrl(raw: String): String {
            val b = raw.trim().trimEnd('/')
            return if (b.startsWith("http://") || b.startsWith("https://")) b
            else "https://$b"
        }
    }

    private fun open(path: String, method: String, body: String?): HttpURLConnection {
        val conn = URL(normalizeBaseUrl(baseUrl) + path).openConnection()
        if (conn !is HttpURLConnection) {
            // Only reachable for a scheme we do not speak (ftp:, file:)
            // - a clear sentence instead of a ClassCastException.
            throw java.io.IOException("Not an http(s) address: $baseUrl")
        }
        conn.requestMethod = method
        conn.connectTimeout = 10_000
        conn.readTimeout = 15_000
        sessionCookie?.let { conn.setRequestProperty("Cookie", "fxcloud_session=$it") }
        if (body != null) {
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "application/json")
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        }
        return conn
    }

    private fun read(conn: HttpURLConnection): Reply {
        val code = conn.responseCode
        val stream = if (code in 200..299) conn.inputStream else conn.errorStream
        val body = stream?.bufferedReader()?.use { it.readText() } ?: ""
        val setCookie = conn.getHeaderField("Set-Cookie")
        conn.disconnect()
        return Reply(code, body, setCookie)
    }

    fun post(path: String, json: JSONObject): Reply = read(open(path, "POST", json.toString()))
    fun get(path: String): Reply = read(open(path, "GET", null))

    /** POST /api/login; keeps the session cookie on success. */
    fun login(user: String, password: String): Reply {
        val reply = post("/api/login", JSONObject().put("username", user).put("password", password))
        if (reply.code == 200) rememberSession(reply)
        return reply
    }

    /** Restore a stored token (app start) without a network call. */
    fun withSession(token: String): ApiClient {
        sessionCookie = token
        return this
    }

    private fun rememberSession(reply: Reply) {
        // First Set-Cookie is the session: "fxcloud_session=...; Path=/..."
        val raw = reply.setCookie ?: return
        val token = raw.split(";").first().substringAfter("fxcloud_session=", "").trim()
        if (token.isNotEmpty()) sessionCookie = token
    }

    /** GET /api/me - who am I (id for mount detection), flat JSON. */
    fun me(): Long {
        val reply = get("/api/me")
        require(reply.code == 200) { "session expired (${reply.code})" }
        return JSONObject(reply.body).optLong("id", -1)
    }

    /**
     * GET /api/files/download?id= - the raw bytes: the FXE1 container
     * when the row is encrypted (the server answers octet-stream, it
     * cannot read them), the plaintext with its mime otherwise.
     */
    fun download(id: Long): ByteArray {
        val conn = open("/api/files/download?id=$id", "GET", null)
        val code = conn.responseCode
        if (code !in 200..299) {
            conn.disconnect()
            throw java.io.IOException("download failed ($code)")
        }
        val bytes = conn.inputStream.use { it.readBytes() }
        conn.disconnect()
        return bytes
    }

    /** GET /api/keys/me - the wrapped material, or null when the
     *  account has no encryption set up (404 is the normal answer). */
    fun keysOrNull(): String? {
        val reply = get("/api/keys/me")
        if (reply.code != 200) return null
        return JSONObject(reply.body).getJSONObject("keys").toString()
    }
}
