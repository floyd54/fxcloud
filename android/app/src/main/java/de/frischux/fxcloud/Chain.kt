package de.frischux.fxcloud

import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

/** One row of a listing, as the screens see it. */
data class Row(
    val id: Long,
    val name: String,
    val isDir: Boolean,
    val size: Long,
    val parentId: Long?,
    val ownerId: Long,
    val nameEnc: Int,
    val encVersion: Int,
    val encKey: String?,
    val mime: String?
) {
    companion object {
        fun from(o: JSONObject): Row = Row(
            id = o.getLong("id"),
            name = o.getString("name"),
            isDir = o.optBoolean("is_dir", false),
            size = o.optLong("size", 0),
            parentId = if (o.isNull("parent_id")) null else o.getLong("parent_id"),
            ownerId = o.optLong("owner_id", -1),
            nameEnc = o.optInt("name_enc", 0),
            encVersion = o.optInt("enc_version", 0),
            encKey = if (o.isNull("enc_key")) null else o.getString("enc_key"),
            mime = if (o.isNull("mime")) null else o.getString("mime")
        )
    }
}

/** One breadcrumb segment. */
data class Crumb(val id: Long?, val name: String, val nameEnc: Int, val namesEnc: Int)

/**
 * The app's key chain (concepts/android.md A4): the same walk
 * fxcrypto.js `resolveFileKey` does - down the breadcrumb unwrapping
 * records - after which a row's name opens with its parent's key (N2).
 *
 * Own tree only in S2: a mount's key sits inside a share envelope, and
 * opening envelopes is S3. Names that do not open show a placeholder
 * instead of a blob.
 */
object Chain {
    private val cache = HashMap<Long, ByteArray>()

    /** source id -> the key its envelope opened for me (5.5). */
    private val shareKeys = HashMap<Long, ByteArray>()

    /** My username: the grantee half of the share AAD (N4). */
    private var grantee: String? = null

    fun clear() {
        cache.clear()
        shareKeys.clear()
        grantee = null
    }

    /** One decoder for both encodings (standard and url-safe). */
    fun decodeB64(s: String): ByteArray = try {
        Base64.getDecoder().decode(s)
    } catch (e: Throwable) {
        Base64.getUrlDecoder().decode(s)
    }

    /**
     * Open every envelope sealed to me (S3d): `GET /api/shares/incoming`,
     * the packed session's private key, the share AAD - the web's
     * openEnvelopes. One envelope that fails to open skips itself: a
     * broken share must not take the others down.
     */
    fun openShares(api: ApiClient, username: String, pkcs8: ByteArray): Int {
        shareKeys.clear()
        grantee = username
        val reply = api.get("/api/shares/incoming")
        if (reply.code != 200) return 0
        val shares = JSONObject(reply.body).getJSONArray("shares")
        var opened = 0
        for (i in 0 until shares.length()) {
            val s = shares.getJSONObject(i)
            if (s.isNull("envelope")) continue // plaintext share: nothing sealed
            try {
                val envelope = decodeB64(s.getString("envelope"))
                val sourceId = s.getLong("file_id")
                shareKeys[sourceId] = FxCore.eciesOpen(envelope, pkcs8, sourceId, username)
                opened++
            } catch (e: Throwable) {
                // one broken envelope skips itself
            }
        }
        return opened
    }

    /** N4: a mount's display label - the shared node's key, the share
     *  AAD, the very bytes the sharer sealed with. */
    private fun mountName(id: Long, blob: String): String? {
        val key = shareKeys[id] ?: return null
        val who = grantee ?: return null
        return try {
            String(FxCore.unwrap(key, blob, FxCore.shareEnvelopeAad(id, who)), Charsets.UTF_8)
        } catch (e: Throwable) {
            null
        }
    }

    /** The first real crumb decides where a walk starts (5.5): my root
     *  key, or the key an envelope opened for a mount - whose own
     *  record then comes from the envelope (returns null when the path
     *  starts in my own tree). */
    private fun mountStart(crumbs: JSONArray): Pair<ByteArray, Int>? {
        val firstRow = (0 until crumbs.length())
            .firstOrNull { !crumbs.getJSONObject(it).isNull("id") } ?: return null
        val shareKey = shareKeys[crumbs.getJSONObject(firstRow).getLong("id")] ?: return null
        return shareKey to (firstRow + 1)
    }

    /** The key wrapping `folderId`'s children; null = the root key. */
    fun keyFor(api: ApiClient, rootKey: ByteArray, folderId: Long?): ByteArray {
        if (folderId == null) return rootKey
        cache[folderId]?.let { return it }
        val reply = api.get("/api/files/breadcrumb?id=$folderId")
        require(reply.code == 200) { "breadcrumb: ${reply.code}" }
        val crumbs = JSONObject(reply.body).getJSONArray("breadcrumbs")
        var key = rootKey
        var start = 0
        mountStart(crumbs)?.let { (shareKey, from) ->
            key = shareKey
            start = from // the mount's own record came from the envelope
        }
        for (i in start until crumbs.length()) {
            val c = crumbs.getJSONObject(i)
            if (c.isNull("id") || c.isNull("enc_key")) continue
            key = FxCore.unwrapChild(key, c.getLong("id"), c.getString("enc_key"))
        }
        cache[folderId] = key
        return key
    }

    /** Fresh bytes for keys and temp names (S3). */
    fun randomBytes(n: Int): ByteArray {
        val bytes = ByteArray(n)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes
    }

    /**
     * The folder's key for a write: the same walk as `keyFor`, but a
     * folder whose record is missing (created before the account was
     * encrypted) gains one here - the web's `ensureChainKey`. Upload is
     * the only caller; reads never write, so `keyFor` stays pure and a
     * recordless folder shows placeholders there (S2's rule).
     */
    fun ensureKey(api: ApiClient, rootKey: ByteArray, folderId: Long?): ByteArray {
        if (folderId == null) return rootKey
        val reply = api.get("/api/files/breadcrumb?id=$folderId")
        require(reply.code == 200) { "breadcrumb: ${reply.code}" }
        val crumbs = JSONObject(reply.body).getJSONArray("breadcrumbs")
        var key = rootKey
        var start = 0
        mountStart(crumbs)?.let { (shareKey, from) ->
            key = shareKey
            start = from // a mount's record came from its envelope
        }
        for (i in start until crumbs.length()) {
            val c = crumbs.getJSONObject(i)
            if (c.isNull("id")) continue
            val id = c.getLong("id")
            if (!c.isNull("enc_key")) {
                key = FxCore.unwrapChild(key, id, c.getString("enc_key"))
            } else {
                // No record yet: this folder's key is brand new, wrapped
                // under whatever the walk holds (its parent's key).
                val fresh = randomBytes(32)
                val wrapped = FxCore.wrapChild(key, id, fresh)
                api.putKey(id, java.util.Base64.getEncoder().encodeToString(wrapped))
                key = fresh
            }
        }
        cache[folderId] = key
        return key
    }

    /**
     * The value an envelope seals (5.5): the folder's key - after the
     * web's ensureChainKey plus the keySubtree fix-up - or the file's
     * content key; null when there is nothing to seal (plaintext row).
     */
    fun shareSealValue(api: ApiClient, rootKey: ByteArray, entry: Row): ByteArray? {
        if (entry.isDir) {
            val folderKey = ensureKey(api, rootKey, entry.id)
            rebindSubtree(api, rootKey, entry.id)
            return folderKey
        }
        if (entry.encVersion > 0 && entry.encKey != null) {
            val parentKey = keyFor(api, rootKey, entry.parentId)
            return FxCore.unwrapChild(parentKey, entry.id, entry.encKey!!)
        }
        return null
    }

    /**
     * keySubtree (5.5): every encrypted file's record opens under its
     * parent, so one envelope reaches every level below the mount.
     * Legacy records (wrapped to the root key) are re-bound to the
     * parent; a record that already opens where it stands is left
     * alone - the web's unconditional re-bind, minus the writes.
     */
    fun rebindSubtree(api: ApiClient, rootKey: ByteArray, folderId: Long) {
        val reply = api.get("/api/files?parent=$folderId")
        require(reply.code == 200) { "listing: ${reply.code}" }
        val entries = JSONObject(reply.body).getJSONArray("entries")
        val parentKey = ensureKey(api, rootKey, folderId)
        for (i in 0 until entries.length()) {
            val row = Row.from(entries.getJSONObject(i))
            if (row.isDir) {
                rebindSubtree(api, rootKey, row.id)
                continue
            }
            if (row.encVersion == 0 || row.encKey == null) continue
            val bound = try {
                FxCore.unwrapChild(parentKey, row.id, row.encKey!!)
                true
            } catch (e: Throwable) {
                false
            }
            if (bound) continue
            // Legacy flat record (5.4): wrapped straight to my root key.
            val raw = FxCore.unwrapChild(rootKey, row.id, row.encKey!!)
            val wrapped = FxCore.wrapChild(parentKey, row.id, raw)
            api.putKey(row.id, java.util.Base64.getEncoder().encodeToString(wrapped))
        }
    }

    /**
     * The N4 display label for a name-flagged row: its key + the share
     * AAD, url-safe like the web's b64url; null when there is no blob
     * to write or no key to wrap it under.
     */
    fun shareLabel(entry: Row, sealKey: ByteArray?, grantee: String): String? {
        if (entry.nameEnc == 0 || sealKey == null) return null
        val wrapped = FxCore.wrap(
            sealKey,
            entry.name.toByteArray(Charsets.UTF_8),
            FxCore.shareEnvelopeAad(entry.id, grantee)
        )
        return Base64.getUrlEncoder().encodeToString(wrapped)
    }

    /**
     * Decrypt a row's name in place of the stored text; anything that
     * does not open (a mount, a foreign row) keeps a placeholder - a
     * listing must never fail because one name is mid-migration.
     */
    fun decryptName(api: ApiClient, rootKey: ByteArray, entry: Row): String {
        if (entry.nameEnc == 0) return entry.name
        // N4: a mount's label wraps under the shared node's key with
        // the share AAD - no parent in the picture.
        if (shareKeys.containsKey(entry.id)) {
            return mountName(entry.id, entry.name) ?: "(encrypted)"
        }
        return try {
            val parentKey = keyFor(api, rootKey, entry.parentId)
            String(FxCore.unwrapChild(parentKey, entry.id, entry.name), Charsets.UTF_8)
        } catch (e: Throwable) {
            "(encrypted)"
        }
    }

    /**
     * Decrypt every crumb's own name, walking the same chain. A null
     * rootKey means an account without encryption - there are no records
     * to advance through and no wrapped names to open.
     */
    fun decryptCrumbs(api: ApiClient, rootKey: ByteArray?, crumbs: JSONArray): List<Crumb> {
        val out = ArrayList<Crumb>(crumbs.length())
        var key = rootKey
        // The first real row decides where the walk starts (5.5): my
        // root key, or the key an envelope opened for a mount - whose
        // own record then comes from the envelope, not from a parent.
        var mountId: Long? = null
        mountStart(crumbs)?.let { (shareKey, _) ->
            key = shareKey
            mountId = crumbs.getJSONObject(
                (0 until crumbs.length()).first { !crumbs.getJSONObject(it).isNull("id") }
            ).getLong("id")
        }
        for (i in 0 until crumbs.length()) {
            val c = crumbs.getJSONObject(i)
            val id = if (c.isNull("id")) null else c.getLong("id")
            var name = c.getString("name")
            val nameEnc = c.optInt("name_enc", 0)
            val namesEnc = c.optInt("names_enc", 0)
            if (id != null && nameEnc != 0 && key != null) {
                name = try {
                    if (id == mountId) {
                        // The mount crumb's name is the share label (N4).
                        mountName(id, name) ?: "(encrypted)"
                    } else {
                        String(FxCore.unwrapChild(key, id, name), Charsets.UTF_8)
                    }
                } catch (e: Throwable) {
                    "(encrypted)"
                }
            }
            out.add(Crumb(id, name, nameEnc, namesEnc))
            if (id != null && id != mountId && key != null && !c.isNull("enc_key")) {
                key = try {
                    FxCore.unwrapChild(key, id, c.getString("enc_key"))
                } catch (e: Throwable) {
                    return out // the chain stops: show what opened
                }
            }
        }
        return out
    }

    /** Base64 for the rare direct use (fingerprints later). */
    fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
}
