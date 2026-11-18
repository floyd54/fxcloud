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
    val nameEnc: Int
) {
    companion object {
        fun from(o: JSONObject): Row = Row(
            id = o.getLong("id"),
            name = o.getString("name"),
            isDir = o.optBoolean("is_dir", false),
            size = o.optLong("size", 0),
            parentId = if (o.isNull("parent_id")) null else o.getLong("parent_id"),
            ownerId = o.optLong("owner_id", -1),
            nameEnc = o.optInt("name_enc", 0)
        )
    }
}

/** One breadcrumb segment. */
data class Crumb(val id: Long?, val name: String, val nameEnc: Int)

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

    fun clear() = cache.clear()

    /** The key wrapping `folderId`'s children; null = the root key. */
    fun keyFor(api: ApiClient, rootKey: ByteArray, folderId: Long?): ByteArray {
        if (folderId == null) return rootKey
        cache[folderId]?.let { return it }
        val reply = api.get("/api/files/breadcrumb?id=$folderId")
        require(reply.code == 200) { "breadcrumb: ${reply.code}" }
        val crumbs = JSONObject(reply.body).getJSONArray("breadcrumbs")
        var key = rootKey
        for (i in 0 until crumbs.length()) {
            val c = crumbs.getJSONObject(i)
            if (c.isNull("id") || c.isNull("enc_key")) continue
            key = FxCore.unwrapChild(key, c.getLong("id"), c.getString("enc_key"))
        }
        cache[folderId] = key
        return key
    }

    /**
     * Decrypt a row's name in place of the stored text; anything that
     * does not open (a mount, a foreign row) keeps a placeholder - a
     * listing must never fail because one name is mid-migration.
     */
    fun decryptName(api: ApiClient, rootKey: ByteArray, entry: Row): String {
        if (entry.nameEnc == 0) return entry.name
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
        for (i in 0 until crumbs.length()) {
            val c = crumbs.getJSONObject(i)
            val id = if (c.isNull("id")) null else c.getLong("id")
            var name = c.getString("name")
            val nameEnc = c.optInt("name_enc", 0)
            if (id != null && nameEnc != 0 && key != null) {
                name = try {
                    String(FxCore.unwrapChild(key, id, name), Charsets.UTF_8)
                } catch (e: Throwable) {
                    "(encrypted)"
                }
            }
            out.add(Crumb(id, name, nameEnc))
            if (id != null && key != null && !c.isNull("enc_key")) {
                key = try {
                    FxCore.unwrapChild(key, id, c.getString("enc_key"))
                } catch (e: Throwable) {
                    return out // a mount's key is an envelope: S3 opens it
                }
            }
        }
        return out
    }

    /** Base64 for the rare direct use (fingerprints later). */
    fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
}
