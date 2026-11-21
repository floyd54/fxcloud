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

    /** POST /api/register - the web's register tab: an active account
     *  comes back with its session cookie (200), a pending one with202
     *  and no cookie; both answers are the caller's to interpret. */
    fun register(user: String, password: String, displayName: String?): Reply {
        val body = JSONObject()
            .put("username", user)
            .put("password", password)
        if (displayName != null) body.put("display_name", displayName)
        val reply = post("/api/register", body)
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
     *  share AAD binds to - the account's auto-unlock switch
     *  (server-side flag of DECISION 7), the display name and theme
     *  (empty theme = system), flat JSON from GET /api/me. */
    data class Me(
        val id: Long,
        val username: String,
        val autoUnlock: Boolean,
        val displayName: String,
        val theme: String
    )

    fun me(): Me {
        val reply = get("/api/me")
        require(reply.code == 200) { "session expired (${reply.code})" }
        val o = JSONObject(reply.body)
        return Me(
            o.optLong("id", -1),
            o.optString("username", ""),
            o.optBoolean("auto_unlock", false),
            o.optString("display_name", ""),
            o.optString("theme", "")
        )
    }

    /**
     * PUT /api/me - the settings dialog's sections save independently,
     * so only the fields present move (the server answers "nothing to
     * update" for an empty body). Returns the updated me().
     */
    fun updateMe(
        displayName: String? = null,
        autoUnlock: Boolean? = null
    ): Me {
        val body = JSONObject()
        if (displayName != null) body.put("display_name", displayName)
        if (autoUnlock != null) body.put("auto_unlock", autoUnlock)
        require(body.length() > 0) { "nothing to update" }
        val conn = open("/api/me", "PUT", body.toString())
        val reply = read(conn)
        if (reply.code != 200) serverError(reply, "Settings")
        val o = JSONObject(reply.body)
        return Me(
            o.optLong("id", -1),
            o.optString("username", ""),
            o.optBoolean("auto_unlock", false),
            o.optString("display_name", ""),
            o.optString("theme", "")
        )
    }

    /** PUT /api/me/password - the current password has to match, the
     *  new one is at least8 characters (the web's settings dialog). */
    fun changePassword(current: String, new: String) {
        val body = JSONObject()
            .put("current_password", current)
            .put("new_password", new)
        val reply = open("/api/me/password", "PUT", body.toString()).let { read(it) }
        if (reply.code != 200) serverError(reply, "Password")
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

    /** POST /api/files/folder {parent_id, name} - a new empty folder
     *  (the temp+rename dance for names-at-rest happens in the caller,
     *  like the web's newFolder). Returns the new id. */
    fun createFolder(parentId: Long?, name: String): Long {
        val body = JSONObject()
        if (parentId == null) {
            body.put("parent_id", JSONObject.NULL)
        } else {
            body.put("parent_id", parentId)
        }
        body.put("name", name)
        val reply = post("/api/files/folder", body)
        if (reply.code != 200) serverError(reply, "Create folder")
        return JSONObject(reply.body).getJSONObject("entry").getLong("id")
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
     * timeout: this is the upload itself. `dropHistory` is the
     * rotation's destructive half: old versions fall with the old key.
     */
    fun putContent(id: Long, bytes: ByteArray, encKeyB64: String?, dropHistory: Boolean = false) {
        val path = buildString {
            append("/api/files/content?id=").append(id)
            if (encKeyB64 != null) {
                append("&enc=1&key=").append(URLEncoder.encode(encKeyB64, "UTF-8"))
            }
            if (dropHistory) append("&history=drop")
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

    // ------------------------------------------------------------- trash (S5a)

    /** A trashed entry: the row itself plus the two dates that say
     *  when it arrived and when it goes for good. */
    data class Trashed(val row: Row, val deletedAt: String, val purgeAt: String)

    fun trashList(): List<Trashed> {
        val reply = get("/api/files/trash")
        if (reply.code != 200) serverError(reply, "Trash")
        val arr = JSONObject(reply.body).getJSONArray("entries")
        val out = ArrayList<Trashed>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            out.add(
                Trashed(
                    Row.from(o),
                    if (o.isNull("deleted_at")) "" else o.getString("deleted_at"),
                    if (o.isNull("purge_at")) "" else o.getString("purge_at")
                )
            )
        }
        return out
    }

    /** POST /api/files/trash/restore {id} - back to where it was. */
    fun restoreTrash(id: Long) {
        val reply = post("/api/files/trash/restore", JSONObject().put("id", id))
        if (reply.code != 200) serverError(reply, "Restore")
    }

    /** POST /api/files/trash/purge {id} - gone for good. */
    fun purgeTrash(id: Long) {
        val reply = post("/api/files/trash/purge", JSONObject().put("id", id))
        if (reply.code != 200) serverError(reply, "Purge")
    }

    /** POST /api/files/trash/empty - the web's "empty trash". */
    fun emptyTrash() {
        val reply = post("/api/files/trash/empty", JSONObject())
        if (reply.code != 200) serverError(reply, "Empty trash")
    }

    // ----------------------------------------------------------- versions (S5c)

    /** A kept version of a file: when it was made, how big, and whether
     *  its bytes are a container of its time (enc_version of THAT save). */
    data class Version(
        val id: Long,
        val size: Long,
        val encVersion: Int,
        val createdAt: String
    )

    /** GET /api/files/versions?id= - the web's version list. */
    fun versions(fileId: Long): List<Version> {
        val reply = get("/api/files/versions?id=$fileId")
        if (reply.code != 200) serverError(reply, "Versions")
        val arr = JSONObject(reply.body).getJSONArray("versions")
        val out = ArrayList<Version>(arr.length())
        for (i in 0 until arr.length()) {
            val v = arr.getJSONObject(i)
            out.add(
                Version(
                    v.getLong("id"),
                    v.optLong("size", 0),
                    v.optInt("enc_version", 0),
                    if (v.isNull("created_at")) "" else v.getString("created_at")
                )
            )
        }
        return out
    }

    /** GET /api/files/version/download?id=&vid= - one kept version's
     *  bytes (the container of its time for encrypted rows). */
    fun downloadVersion(fileId: Long, versionId: Long): ByteArray {
        val conn = open("/api/files/version/download?id=$fileId&vid=$versionId", "GET", null)
        val code = conn.responseCode
        if (code !in 200..299) {
            conn.disconnect()
            throw java.io.IOException("Version download failed ($code)")
        }
        val bytes = conn.inputStream.use { it.readBytes() }
        conn.disconnect()
        return bytes
    }

    /** POST /api/files/version/restore?id=&vid= - the version becomes
     *  the current file (history renumbers, the row is new). */
    fun restoreVersion(fileId: Long, versionId: Long) {
        val conn = open("/api/files/version/restore?id=$fileId&vid=$versionId", "POST", "{}")
        val reply = read(conn)
        if (reply.code != 200) serverError(reply, "Restore version")
    }

    /** DELETE /api/files/version?id=&vid= - drop one kept version. */
    fun deleteVersion(fileId: Long, versionId: Long) {
        val conn = openRaw("/api/files/version?id=$fileId&vid=$versionId", "DELETE", 15_000)
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
                if (msg.isNotEmpty()) "Delete version: $msg" else "Delete version ($code)"
            )
        }
        conn.inputStream.use { it.readBytes() }
        conn.disconnect()
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

    /** One share I created (GET /api/shares/outgoing[?file_id=]). */    data class Outgoing(
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

    /** One item of a share batch: sealed envelope and N4 label when
     *  the row carries keys, omitted for plaintext. */
    data class ShareItem(val fileId: Long, val envelope: String?, val displayName: String?)

    /** POST /api/shares/batch - the web sends its whole selection in
     *  one request (a single item is an array of one); answers
     *  {ok: [], failed: [{id, name, error}]} (returned unparsed). */
    fun shareBatch(
        items: List<ShareItem>,
        username: String,
        permissions: Int
    ): JSONObject {
        val arr = JSONArray()
        for (it in items) {
            val item = JSONObject().put("file_id", it.fileId)
            if (it.envelope != null) item.put("envelope", it.envelope)
            if (it.displayName != null) item.put("display_name", it.displayName)
            arr.put(item)
        }
        val body = JSONObject()
            .put("items", arr)
            .put("username", username)
            .put("permissions", permissions)
        val reply = post("/api/shares/batch", body)
        if (reply.code != 200) serverError(reply, "Share")
        return JSONObject(reply.body)
    }

    /**
     * Copy or move rows to `dest` (null = my root): one item takes the
     * single routes ({id, dest_parent}), a selection the batch ones
     * ({ids, dest_parent}) - same semantics, the web uses both too.
     * Answers {ok, failed} for batches, {entry} for single moves.
     */
    fun transfer(copy: Boolean, ids: List<Long>, dest: Long?): JSONObject {
        require(ids.isNotEmpty()) { "nothing to transfer" }
        val single = ids.size == 1
        val path = when {
            single && copy -> "/api/files/copy"
            single -> "/api/files/move"
            copy -> "/api/files/batch/copy"
            else -> "/api/files/batch/move"
        }
        val body = JSONObject()
        if (single) body.put("id", ids[0]) else body.put("ids", JSONArray(ids))
        if (dest == null) body.put("dest_parent", JSONObject.NULL)
        else body.put("dest_parent", dest)
        val reply = post(path, body)
        if (reply.code != 200) serverError(reply, if (copy) "Copy" else "Move")
        return if (reply.body.isBlank()) JSONObject() else JSONObject(reply.body)
    }

    /** POST /api/files/batch/delete - the trash (S5 shows it; until
     *  then the web's trash holds what this sends). Answers {ok,
     *  failed} like the other batches. */
    fun trash(ids: List<Long>): JSONObject {
        val body = JSONObject().put("ids", JSONArray(ids))
        val reply = post("/api/files/batch/delete", body)
        if (reply.code != 200) serverError(reply, "Delete")
        return if (reply.body.isBlank()) JSONObject() else JSONObject(reply.body)
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

    /** PUT /api/shares/{id} - re-seal an envelope of mine to a fresh
     *  key (rotation: nobody's grant may go stale,5.5). */
    fun putShareEnvelope(id: Long, envelopeB64: String) {
        val reply = open(
            "/api/shares/$id", "PUT",
            JSONObject().put("envelope", envelopeB64).toString()
        ).let { read(it) }
        if (reply.code != 200) serverError(reply, "Re-seal")
    }

    /** GET /api/keys/me - the wrapped material, or null when the
     *  account has no encryption set up (404 is the normal answer). */
    fun keysOrNull(): String? {
        val reply = get("/api/keys/me")
        if (reply.code != 200) return null
        return JSONObject(reply.body).getJSONObject("keys").toString()
    }
}
