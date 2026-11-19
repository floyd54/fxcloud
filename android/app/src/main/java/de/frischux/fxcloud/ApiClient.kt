package de.frischux.fxcloud

import java.net.HttpURLConnection
import java.net.URLEncoder
import java.net.URL
import org.json.JSONArray
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

    private fun openRaw(path: String, method: String, readTimeoutMs: Int): HttpURLConnection {
        val conn = URL(normalizeBaseUrl(baseUrl) + path).openConnection()
        if (conn !is HttpURLConnection) {
            // Only reachable for a scheme we do not speak (ftp:, file:)
            // - a clear sentence instead of a ClassCastException.
            throw java.io.IOException("Not an http(s) address: $baseUrl")
        }
        conn.requestMethod = method
        conn.connectTimeout = 10_000
        conn.readTimeout = readTimeoutMs
        sessionCookie?.let { conn.setRequestProperty("Cookie", "fxcloud_session=$it") }
        return conn
    }

    private fun open(path: String, method: String, body: String?): HttpURLConnection {
        val conn = openRaw(path, method, 15_000)
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

    /** Who am I: id (mount detection), username - the grantee the
     *  share AAD binds to - and the account's auto-unlock switch
     *  (server-side flag of DECISION 7), flat JSON from GET /api/me. */
    data class Me(val id: Long, val username: String, val autoUnlock: Boolean)

    fun me(): Me {
        val reply = get("/api/me")
        require(reply.code == 200) { "session expired (${reply.code})" }
        val o = JSONObject(reply.body)
        return Me(
            o.optLong("id", -1),
            o.optString("username", ""),
            o.optBoolean("auto_unlock", false)
        )
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

    /** Fail with the server's own message when it sent one. */
    private fun serverError(reply: Reply, what: String): Nothing {
        val msg = try {
            JSONObject(reply.body).optString("error")
        } catch (e: Throwable) {
            ""
        }
        throw java.io.IOException(
            if (msg.isNotEmpty()) "$what: $msg" else "$what (${reply.code})"
        )
    }

    /** POST /api/files/file - a new empty row (blob included); parent
     *  null = root. The id comes back for the two-phase write. */
    fun createFile(parentId: Long?, name: String): Long {
        val body = JSONObject()
        if (parentId == null) {
            body.put("parent_id", JSONObject.NULL)
        } else {
            body.put("parent_id", parentId)
        }
        body.put("name", name)
        val reply = post("/api/files/file", body)
        if (reply.code != 200) serverError(reply, "Create")
        return JSONObject(reply.body).getJSONObject("entry").getLong("id")
    }

    /** POST /api/files/rename - phase two of a name-at-rest upload. */
    fun rename(id: Long, name: String) {
        val reply = post("/api/files/rename", JSONObject().put("id", id).put("name", name))
        if (reply.code != 200) serverError(reply, "Rename")
    }

    /** PUT /api/files/key - give a folder its key record (5.4). */
    fun putKey(id: Long, keyB64: String) {
        val reply = open(
            "/api/files/key", "PUT",
            JSONObject().put("id", id).put("key", keyB64).toString()
        ).let { read(it) }
        if (reply.code != 200) serverError(reply, "Key record")
    }

    /**
     * PUT /api/files/content?id= - the body is the FXE1 container when
     * `encKeyB64` is given (enc=1&key=, standard base64 like the web's
     * encodeURIComponent), the plaintext otherwise. Generous read
     * timeout: this is the upload itself.
     */
    fun putContent(id: Long, bytes: ByteArray, encKeyB64: String?) {
        val path = if (encKeyB64 != null) {
            "/api/files/content?id=$id&enc=1&key=" +
                URLEncoder.encode(encKeyB64, "UTF-8")
        } else {
            "/api/files/content?id=$id"
        }
        val conn = openRaw(path, "PUT", 120_000)
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/octet-stream")
        conn.outputStream.use { it.write(bytes) }
        val code = conn.responseCode
        val stream = if (code in 200..299) conn.inputStream else conn.errorStream
        val body = stream?.bufferedReader()?.use { it.readText() } ?: ""
        conn.disconnect()
        if (code !in 200..299) {
            val msg = try {
                JSONObject(body).optString("error")
            } catch (e: Throwable) {
                ""
            }
            throw java.io.IOException(
                if (msg.isNotEmpty()) "Save: $msg" else "Save ($code)"
            )
        }
    }

    /**
     * Undo a row that was created but could not be written: delete it
     * and empty the trash entry - the web's discardCreated, best
     * effort, because the caller is already reporting the failure.
     */
    fun discard(id: Long) {
        try {
            post("/api/files/batch/delete", JSONObject().put("ids", JSONArray().put(id)))
        } catch (e: Throwable) {
            // already gone
        }
        try {
            post("/api/files/trash/purge", JSONObject().put("id", id))
        } catch (e: Throwable) {
            // already gone
        }
    }

    // ------------------------------------------------------------ sharing (S4a)

    /** One account as the share dialog lists it (GET /api/users). */
    data class Target(val username: String, val displayName: String, val active: Boolean)

    fun users(): List<Target> {
        val reply = get("/api/users")
        if (reply.code != 200) serverError(reply, "Accounts")
        val arr = JSONArray(reply.body)
        val out = ArrayList<Target>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out.add(
                Target(
                    o.getString("username"),
                    o.optString("display_name", ""),
                    o.optBoolean("is_active", true)
                )
            )
        }
        return out
    }

    /** The grantee's public key + fingerprint; null on404 - the account
     *  has no key row and can only receive plaintext shares. */
    data class PublicKey(val public: String, val fingerprint: String)

    fun publicKeyOf(username: String): PublicKey? {
        val reply = get("/api/keys/" + URLEncoder.encode(username, "UTF-8"))
        if (reply.code == 404) return null
        if (reply.code != 200) serverError(reply, "Public key")
        val key = JSONObject(reply.body).getJSONObject("key")
        return PublicKey(key.getString("public_key"), key.getString("fingerprint"))
    }

    /** One share I created (GET /api/shares/outgoing[?file_id=]). */
    data class Outgoing(
        val id: Long,
        val fileId: Long,
        val username: String,
        val permissions: Int,
        val permissionNames: List<String>
    )

    fun outgoingShares(fileId: Long?): List<Outgoing> {
        val path = if (fileId == null) {
            "/api/shares/outgoing"
        } else {
            "/api/shares/outgoing?file_id=$fileId"
        }
        val reply = get(path)
        if (reply.code != 200) serverError(reply, "Outgoing shares")
        val arr = JSONObject(reply.body).getJSONArray("shares")
        val out = ArrayList<Outgoing>(arr.length())
        for (i in 0 until arr.length()) {
            val s = arr.getJSONObject(i)
            val names = ArrayList<String>()
            val pn = s.optJSONArray("permission_names")
            if (pn != null) {
                for (j in 0 until pn.length()) names.add(pn.getString(j))
            }
            out.add(
                Outgoing(
                    s.getLong("id"),
                    s.getLong("file_id"),
                    s.getString("username"),
                    s.optInt("permissions", 0),
                    names
                )
            )
        }
        return out
    }

    /**
     * POST /api/shares/batch - the web sends a single item as a
     * one-element array too; answers {ok: [], failed: [{id, name,
     * error}]} (returned unparsed for the caller's notice).
     */
    fun shareBatch(
        fileId: Long,
        username: String,
        permissions: Int,
        envelope: String?,
        displayName: String?
    ): JSONObject {
        val item = JSONObject().put("file_id", fileId)
        if (envelope != null) item.put("envelope", envelope)
        if (displayName != null) item.put("display_name", displayName)
        val body = JSONObject()
            .put("items", JSONArray().put(item))
            .put("username", username)
            .put("permissions", permissions)
        val reply = post("/api/shares/batch", body)
        if (reply.code != 200) serverError(reply, "Share")
        return JSONObject(reply.body)
    }

    /** DELETE /api/shares/{id} - revoke one of my shares. */
    fun revokeShare(id: Long) {
        val conn = openRaw("/api/shares/$id", "DELETE", 15_000)
        val code = conn.responseCode
        if (code !in 200..299) {
            val stream = conn.errorStream
            val body = stream?.bufferedReader()?.use { it.readText() } ?: ""
            conn.disconnect()
            val msg = try {
                JSONObject(body).optString("error")
            } catch (e: Throwable) {
                ""
            }
            throw java.io.IOException(
                if (msg.isNotEmpty()) "Revoke: $msg" else "Revoke ($code)"
            )
        }
        conn.inputStream.use { it.readBytes() }
        conn.disconnect()
    }

    /** GET /api/keys/me - the wrapped material, or null when the
     *  account has no encryption set up (404 is the normal answer). */
    fun keysOrNull(): String? {
        val reply = get("/api/keys/me")
        if (reply.code != 200) return null
        return JSONObject(reply.body).getJSONObject("keys").toString()
    }
}
