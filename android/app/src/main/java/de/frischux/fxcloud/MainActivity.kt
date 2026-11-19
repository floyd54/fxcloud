package de.frischux.fxcloud

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.ByteArrayInputStream
import org.json.JSONArray
import org.json.JSONObject

/** The three stops of S2: sign in, unlock (encrypted accounts), browse. */
private enum class Step { LOGIN, PASSPHRASE, FILES }

/** What a preview can show in v1 (S3b): image and text, nothing else. */
private enum class Kind { IMAGE, TEXT, OTHER }

/** The extension tables of the web's PREVIEW_EXT, minus what the app
 *  cannot render in-process (video/audio/pdf/html say so instead). */
private val IMAGE_EXTS = setOf(
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "ico", "apng", "avif"
)
private val TEXT_EXTS = setOf(
    "txt", "text", "md", "markdown", "csv", "tsv", "log", "json", "xml",
    "yml", "yaml", "toml", "ini", "cfg", "conf", "env", "sql", "rst",
    "tex", "diff", "patch", "rs", "js", "mjs", "cjs", "jsx", "ts", "tsx",
    "py", "rb", "go", "java", "c", "h", "cc", "cpp", "hpp", "cs", "php",
    "sh", "bash", "zsh", "pl", "lua", "swift", "kt", "kts", "scala", "r",
    "vue", "svelte", "css", "scss", "sass", "less", "svg"
)

/** A rendered preview (S3b): the row it belongs to (S4c rotates from
 *  the bar), decoded bitmap or text, held in memory. */
private class Preview(
    val row: Row,
    val kind: Kind,
    val bitmap: Bitmap? = null,
    val text: String? = null
)

/** The confirmations the share flow needs before anything is sealed
 *  (TOFU and the web's no-key warning - app.js confirmFingerprint). */
private sealed class ShareDialog {
    data class FirstUse(val user: String, val fp: String, val pub: String, val mask: Int) :
        ShareDialog()

    data class Changed(
        val user: String,
        val old: String,
        val fp: String,
        val pub: String,
        val mask: Int
    ) : ShareDialog()

    data class NoKey(val user: String, val mask: Int) : ShareDialog()
}

/** The AAD under which the ARK rides in a device blob (fxcrypto's
 *  AAD.deviceArk): a purpose tag, so this blob can never be mistaken
 *  for any other wrap. */
private val DEVICE_AAD = "fx1:device-ark:v1".toByteArray(Charsets.UTF_8)

/** The packed session layout (S2, ark tail since S4b): root(32) ||
 *  u32 pkcs8Len || pkcs8 || u32 arkLen || ark. */
private class SessionParts(val root: ByteArray, val pkcs8: ByteArray, val ark: ByteArray)

private fun unpackSession(packed: ByteArray): SessionParts {
    fun u32(at: Int): Int =
        ((packed[at].toInt() and 0xff) shl 24) or
            ((packed[at + 1].toInt() and 0xff) shl 16) or
            ((packed[at + 2].toInt() and 0xff) shl 8) or
            (packed[at + 3].toInt() and 0xff)
    require(packed.size >= 40) { "packed session is ${packed.size} bytes" }
    val pkcs8Len = u32(32)
    require(packed.size >= 40 + pkcs8Len) { "packed session truncated" }
    val arkLen = u32(36 + pkcs8Len)
    require(packed.size == 40 + pkcs8Len + arkLen) { "packed session layout" }
    return SessionParts(
        packed.copyOfRange(0, 32),
        packed.copyOfRange(36, 36 + pkcs8Len),
        packed.copyOfRange(40 + pkcs8Len, packed.size)
    )
}

/**
 * S2: sign in against a live instance, unlock the account material, list
 * the tree with its breadcrumb and decrypt names-at-rest through JNI
 * (concepts/android.md A4-A6). The XML frame is the S1 shape that proved
 * itself on the device; the screens below the header are Compose (A2).
 */
class MainActivity : ComponentActivity() {

    private val prefs by lazy { getSharedPreferences("fxcloud", MODE_PRIVATE) }

    /** Set by login/restore; every call runs on the caller's thread. */
    @Volatile private var api: ApiClient? = null
    @Volatile private var keysJson: String? = null
    @Volatile private var myId: Long = -1

    /** The grantee half of every share AAD (N4) - from /api/me. */
    @Volatile private var myUsername: String = ""

    /** The account's auto-unlock switch (server-side, /api/me). */
    @Volatile private var autoUnlock: Boolean = false

    /**
     * Unlock output and the root key live in memory only - never in
     * prefs, never in a log (DECISION 7): losing them just means
     * unlocking again on the next start, like the browser's reload.
     */
    @Volatile private var packedSession: ByteArray? = null
    @Volatile private var rootKey: ByteArray? = null

    // Compose state, written on the UI thread only.
    private var step by mutableStateOf(Step.LOGIN)
    private var busy by mutableStateOf(false)
    private var notice by mutableStateOf<String?>(null)
    private var rows by mutableStateOf<List<Row>>(emptyList())
    private var crumbs by mutableStateOf<List<Crumb>>(emptyList())
    private var parent by mutableStateOf<Long?>(null)

    /** Non-null replaces the whole list area with the S3b preview. */
    private var preview by mutableStateOf<Preview?>(null)

    /** The S4c confirmation before a key rotation drops history. */
    private var rotateConfirm by mutableStateOf(false)

    /** The system picker for S3c: any file, read through the content
     *  resolver - the picker's URI needs no storage permission. */
    private val pickFile =
        registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
            if (uri != null) doUpload(uri)
        }

    // ------------------------------------------------------------ sharing (S4a)

    /** Non-null replaces the list area with the share screen. */
    private var shareFor by mutableStateOf<Row?>(null)
    private var shareTargets by mutableStateOf<List<ApiClient.Target>>(emptyList())
    private var shareOutgoing by mutableStateOf<List<ApiClient.Outgoing>>(emptyList())
    private var shareTarget by mutableStateOf<String?>(null)
    private var shareKey by mutableStateOf<ApiClient.PublicKey?>(null)
    private var sharePerms by mutableStateOf(setOf(1, 2, 4, 8, 16))
    private var shareDialog by mutableStateOf<ShareDialog?>(null)

    /** The permission checkboxes of the web's share dialog, in order. */
    private val permOptions = listOf(
        1 to "Read", 2 to "Write", 4 to "Create", 8 to "Delete", 16 to "Share"
    )

    /** Folder ids visited since the root - what the system back button
     *  walks out of (UI thread only). */
    private val history = ArrayList<Long?>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Back walks the tree instead of closing the app: up one level,
        // at the passphrase back to the sign-in, at the root out.
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() = goBack()
        })
        try {
            setContentView(R.layout.activity_main)
            // The way out, in the header that has always rendered: it
            // clears the stored session, so the next launch starts fresh.
            findViewById<TextView>(R.id.headerLogout).setOnClickListener { logout() }
            findViewById<ComposeView>(R.id.compose).setContent { AppUi() }
            restoreSession()
        } catch (t: Throwable) {
            // The S1 escape hatch, kept: if even the frame fails, say so
            // where it cannot be missed.
            val msg = "fxcloud S2 failed to start: $t"
            Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
        }
    }

    // ---------------------------------------------------------------- session

    /** A stored session resumes silently: no passphrase, no login form. */
    private fun restoreSession() {
        val base = prefs.getString("base", "") ?: ""
        val token = prefs.getString("session", null)
        if (base.isEmpty() || token == null) {
            step = Step.LOGIN
            return
        }
        busy = true
        Thread {
            try {
                val c = ApiClient(base).withSession(token)
                val me = c.me() // throws when the session is gone
                val keys = c.keysOrNull()
                // Auto-unlock (S4b): the server flag is the truth - off
                // deletes the stored blob, on lets it open the session
                // without a prompt; anything stale or tampered falls
                // back to the pane (the web's adoptDeviceUnlock).
                var adopted: ByteArray? = null
                if (keys != null && prefs.contains("device.${me.id}")) {
                    if (!me.autoUnlock) {
                        prefs.edit().remove("device.${me.id}").apply()
                    } else {
                        adopted = tryAdoptDevice(c, keys, me.id)
                    }
                }
                runOnUiThread {
                    api = c
                    myId = me.id
                    myUsername = me.username
                    autoUnlock = me.autoUnlock
                    keysJson = keys
                    busy = false
                    when {
                        adopted != null -> {
                            packedSession = adopted
                            rootKey = unpackSession(adopted).root
                            step = Step.FILES
                            loadTree()
                        }
                        // Memory-only material: unlock again, exactly like
                        // the browser does after a reload.
                        keys != null -> step = Step.PASSPHRASE
                        else -> {
                            step = Step.FILES
                            loadTree()
                        }
                    }
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    step = Step.LOGIN
                    notice = e.message
                }
            }
        }.start()
    }

    private fun doLogin(server: String, user: String, password: String) {
        busy = true
        notice = null
        Thread {
            try {
                val c = ApiClient(server)
                val reply = c.login(user, password)
                if (reply.code != 200) throw RuntimeException("Sign-in failed (${reply.code})")
                prefs.edit()
                    .putString("base", ApiClient.normalizeBaseUrl(server))
                    .putString("user", user)
                    .putString("session", c.sessionCookie)
                    .apply()
                val me = c.me()
                val keys = c.keysOrNull()
                runOnUiThread {
                    api = c
                    myId = me.id
                    myUsername = me.username
                    autoUnlock = me.autoUnlock
                    keysJson = keys
                    busy = false
                    history.clear()
                    when {
                        keys == null -> {
                            step = Step.FILES
                            loadTree()
                        }
                        // One event (DECISION 3): unless the account opted
                        // into a separate storage secret, the password just
                        // signed in with unlocks right away - the web
                        // carries it across its redirect the same way.
                        separatePassphrase(keys) -> step = Step.PASSPHRASE
                        else -> unlockWith(password, false) { step = Step.PASSPHRASE }
                    }
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = e.message ?: "Sign-in failed"
                }
            }
        }.start()
    }

    private fun doUnlock(password: String) = unlockWith(password, false) { msg ->
        notice = msg ?: "Unlock failed"
    }

    /** The recovery-key pane's way in (S3d): the32-byte key as hex. */
    private fun doRecovery(key: String) = unlockWith(key, true) { msg ->
        notice = msg ?: "Recovery failed"
    }

    /**
     * Argon2id and the ARK chain run in Rust (S2a); a wrong secret
     * throws with the unified unwrap message. `onFail` decides where a
     * failure lands - the passphrase screen after a fresh sign-in (the
     * web's handoff failing is "the pane is the fallback, not an
     * error"), the same screen with a message when typed there.
     */
    private fun unlockWith(secret: String, recovery: Boolean, onFail: (String?) -> Unit) {
        val material = keysJson ?: return
        busy = true
        notice = null
        Thread {
            try {
                val packed = if (recovery) {
                    FxCore.unlockWithRecovery(material, secret)
                } else {
                    FxCore.unlock(material, secret)
                }
                val parts = unpackSession(packed)
                // The private half rides along in the packed session
                // (S2's promise): open every share envelope now (5.5),
                // before the first listing needs them.
                if (myUsername.isNotEmpty()) {
                    api?.let { c -> Chain.openShares(c, myUsername, parts.pkcs8) }
                }
                // Auto-unlock (S4b): while the server's switch is on,
                // keep a device blob like the web keeps one in
                // localStorage - best effort, like the web's.
                if (autoUnlock && parts.ark.isNotEmpty()) {
                    storeDeviceBlob(parts.ark)
                }
                runOnUiThread {
                    packedSession = packed
                    rootKey = parts.root
                    busy = false
                    step = Step.FILES
                    loadTree()
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    onFail(e.message)
                }
            }
        }.start()
    }

    /** The web's handoff skips accounts that chose their own storage
     *  secret (kdf_params.secret === "separate"). */
    private fun separatePassphrase(keys: String): Boolean = try {
        JSONObject(keys).optJSONObject("kdf_params")?.optString("secret") == "separate"
    } catch (e: Throwable) {
        false
    }

    private fun logout() {
        prefs.edit().remove("session").apply()
        Chain.clear()
        packedSession = null
        rootKey = null
        api = null
        keysJson = null
        rows = emptyList()
        crumbs = emptyList()
        parent = null
        history.clear()
        preview = null
        rotateConfirm = false
        shareFor = null
        shareDialog = null
        shareTargets = emptyList()
        shareOutgoing = emptyList()
        shareTarget = null
        shareKey = null
        notice = null
        step = Step.LOGIN
    }

    // ---------------------------------------------------------------- listing

    private fun loadTree() {
        val c = api ?: return
        val target = parent
        busy = true
        notice = null
        Thread {
            try {
                val path = if (target == null) "/api/files" else "/api/files?parent=$target"
                val reply = c.get(path)
                if (reply.code != 200) throw RuntimeException("Listing failed (${reply.code})")
                val arr = JSONObject(reply.body).getJSONArray("entries")
                val parsed = ArrayList<Row>(arr.length())
                for (i in 0 until arr.length()) parsed.add(Row.from(arr.getJSONObject(i)))

                // Names at rest (N2): open what the chain can, keep a
                // placeholder for anything else - a listing never fails
                // because one name is a mount's envelope.
                val rk = rootKey
                if (rk != null) {
                    for (i in parsed.indices) {
                        parsed[i] = parsed[i].copy(name = Chain.decryptName(c, rk, parsed[i]))
                    }
                }
                // The server orders rows by blob under a flag (S3 names-at-
                // rest); restore name order here, directories first.
                parsed.sortWith(
                    compareBy({ if (it.isDir) 0 else 1 }, { it.name.lowercase() })
                )

                val crumbArr: JSONArray = if (target == null) {
                    JSONArray().put(
                        JSONObject().put("id", JSONObject.NULL).put("name", "Home").put("name_enc", 0)
                    )
                } else {
                    val br = c.get("/api/files/breadcrumb?id=$target")
                    if (br.code != 200) throw RuntimeException("Breadcrumb failed (${br.code})")
                    JSONObject(br.body).getJSONArray("breadcrumbs")
                }
                val crumbList = Chain.decryptCrumbs(c, rk, crumbArr)

                runOnUiThread {
                    rows = parsed
                    crumbs = crumbList
                    busy = false
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = e.message
                }
            }
        }.start()
    }

    private fun openFolder(id: Long?) {
        history.add(parent)
        parent = id
        loadTree()
    }

    /** System back: up one directory (history, like the browser's),
     *  back to sign-in from the passphrase, out of the app at the root. */
    private fun goBack() {
        when {
            // The share screen closes first, then a preview, then the
            // tree walks up; at the root of it all the app exits.
            shareFor != null -> {
                shareFor = null
                shareDialog = null
                notice = null
            }
            preview != null -> {
                preview = null
                rotateConfirm = false
            }
            step == Step.FILES && history.isNotEmpty() -> {
                parent = history.removeAt(history.size - 1)
                loadTree()
            }
            step == Step.PASSPHRASE -> {
                notice = null
                step = Step.LOGIN
            }
            else -> finish()
        }
    }

    private fun onRow(row: Row) {
        if (row.isDir) {
            openFolder(row.id)
        } else {
            loadPreview(row)
        }
    }

    // ------------------------------------------------------------- preview (S3b)

    /** The web's previewKind in kind: extension first, sniffed mime second. */
    private fun previewKind(name: String, mime: String?): Kind {
        val ext = name.substringAfterLast('.', "").lowercase()
        if (ext in IMAGE_EXTS) return Kind.IMAGE
        if (ext in TEXT_EXTS) return Kind.TEXT
        if (mime?.startsWith("text/") == true) return Kind.TEXT
        if (mime?.startsWith("image/") == true) return Kind.IMAGE
        return Kind.OTHER
    }

    /**
     * Download, unwrap the content key, decrypt, render - the S3b flow.
     * Kinds the app cannot render never touch the network; every
     * failure lands as a notice, never as a crash.
     */
    private fun loadPreview(row: Row) {
        val c = api ?: return
        val kind = previewKind(row.name, row.mime)
        if (kind == Kind.OTHER) {
            val ext = row.name.substringAfterLast('.', "").uppercase()
            notice = "$ext preview comes later - image and text open today"
            return
        }
        busy = true
        notice = null
        Thread {
            try {
                val raw = c.download(row.id)
                if (raw.size > 50_000_000) {
                    throw RuntimeException("Too large to preview (${raw.size / 1_000_000} MB)")
                }
                val content = if (row.encVersion > 0) {
                    val rk = rootKey ?: throw RuntimeException("Locked - unlock first")
                    val encKey =
                        row.encKey ?: throw RuntimeException("This row carries no key record")
                    val parentKey = Chain.keyFor(c, rk, row.parentId)
                    val contentKey = FxCore.unwrapChild(parentKey, row.id, encKey)
                    FxCore.decryptBytes(row.id, contentKey, raw)
                } else {
                    raw
                }
                val shown = when (kind) {
                    Kind.IMAGE -> {
                        val bitmap = decodeImage(content)
                            ?: throw RuntimeException("This image cannot be displayed")
                        Preview(row, kind, bitmap = bitmap)
                    }
                    else -> {
                        if (content.size > 4_000_000) {
                            throw RuntimeException(
                                "Text too large to display (${content.size / 1_000} KB)"
                            )
                        }
                        Preview(row, kind, text = String(content, Charsets.UTF_8))
                    }
                }
                runOnUiThread {
                    preview = shown
                    busy = false
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Preview failed: ${e.message}"
                }
            }
        }.start()
    }

    /**
     * Decode with a sample size (a modern phone photo would otherwise
     * cost hundreds of MB) and honour the EXIF orientation every
     * camera tags - without it, portraits lie on their side.
     */
    private fun decodeImage(bytes: ByteArray): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sample = 1
        while (bounds.outWidth / sample > 4096 || bounds.outHeight / sample > 4096) {
            sample *= 2
        }
        val bitmap = BitmapFactory.decodeByteArray(
            bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample }
        ) ?: return null
        val orientation = try {
            ExifInterface(ByteArrayInputStream(bytes)).getAttributeInt(
                ExifInterface.TAG_ORIENTATION, ExifInterface.ORIENTATION_NORMAL
            )
        } catch (e: Throwable) {
            ExifInterface.ORIENTATION_NORMAL
        }
        val degrees = when (orientation) {
            ExifInterface.ORIENTATION_ROTATE_90 -> 90f
            ExifInterface.ORIENTATION_ROTATE_180 -> 180f
            ExifInterface.ORIENTATION_ROTATE_270 -> 270f
            else -> 0f
        }
        if (degrees == 0f) return bitmap
        val matrix = Matrix().apply { postRotate(degrees) }
        return Bitmap.createBitmap(
            bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true
        ) ?: bitmap
    }

    // ------------------------------------------------------------- upload (S3c)

    private fun startUpload() {
        if (busy) return
        pickFile.launch("*/*")
    }

    /**
     * The S3c flow, mirrored from app.js/fxenc.js: create the row (a
     * random server-meaningless name under a names_enc folder, then
     * rename to the id-bound blob - N3/N5), give a recordless folder
     * its record (ensureChainKey), fresh file key, encrypt, PUT the
     * container. A failure after the row exists discards it, so no
     * half-written or plaintext leftover stays behind.
     */
    private fun doUpload(uri: Uri) {
        val c = api ?: return
        if (busy) return
        val target = parent
        val namesEnc = rootKey != null && crumbs.lastOrNull()?.namesEnc == 1
        busy = true
        notice = null
        Thread {
            var createdId: Long? = null
            try {
                val name = queryName(uri) ?: "upload.bin"
                val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                    ?: throw RuntimeException("Cannot read the selected file")
                if (bytes.size > 50_000_000) {
                    throw RuntimeException(
                        "Uploads up to50 MB for now (${bytes.size / 1_000_000} MB)"
                    )
                }
                val rk = rootKey
                val parentKey = if (rk == null) null else Chain.ensureKey(c, rk, target)
                val temp = if (namesEnc) {
                    "n" + java.util.Base64.getUrlEncoder()
                        .encodeToString(Chain.randomBytes(16))
                } else {
                    null
                }
                val id = c.createFile(target, temp ?: name)
                createdId = id
                if (temp != null && parentKey != null) {
                    val wrapped = FxCore.wrapChild(
                        parentKey, id, name.toByteArray(Charsets.UTF_8)
                    )
                    c.rename(
                        id,
                        java.util.Base64.getUrlEncoder().encodeToString(wrapped)
                    )
                }
                if (parentKey != null) {
                    val fileKey = Chain.randomBytes(32)
                    val wrappedKey = FxCore.wrapChild(parentKey, id, fileKey)
                    val container = FxCore.encryptBytes(id, fileKey, bytes)
                    c.putContent(
                        id, container, java.util.Base64.getEncoder().encodeToString(wrappedKey)
                    )
                } else {
                    c.putContent(id, bytes, null)
                }
                runOnUiThread {
                    busy = false
                    loadTree() // clears the notice; set it after
                    notice = "Uploaded $name"
                }
            } catch (e: Throwable) {
                createdId?.let { c.discard(it) }
                runOnUiThread {
                    busy = false
                    notice = "Upload failed: ${e.message}"
                }
            }
        }.start()
    }

    private fun queryName(uri: Uri): String? {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (idx >= 0) return cursor.getString(idx)
                }
            }
        return null
    }

    // ------------------------------------------------------------ sharing (S4a)

    /** Long-press on a row: open the share screen and load its world. */
    private fun openShare(row: Row) {
        val c = api ?: return
        if (busy) return
        shareFor = row
        shareTarget = null
        shareKey = null
        sharePerms = setOf(1, 2, 4, 8, 16)
        shareDialog = null
        busy = true
        notice = null
        Thread {
            try {
                val users = c.users()
                val outgoing = c.outgoingShares(row.id)
                runOnUiThread {
                    shareTargets = users
                    shareOutgoing = outgoing
                    busy = false
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    shareFor = null
                    notice = "Share: ${e.message}"
                }
            }
        }.start()
    }

    /** The grantee's fingerprint line (web's showShareFingerprint). */
    private fun selectShareTarget(user: String) {
        val c = api ?: return
        shareTarget = user
        shareKey = null
        busy = true
        Thread {
            try {
                val key = c.publicKeyOf(user)
                runOnUiThread {
                    shareKey = key
                    busy = false
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = e.message
                }
            }
        }.start()
    }

    /** The web's shareAdd: keys first, TOFU, then seal. */
    private fun confirmShare() {
        val c = api ?: return
        val row = shareFor ?: return
        val user = shareTarget ?: run {
            notice = "Pick an account first"
            return
        }
        val mask = sharePerms.sum()
        busy = true
        notice = null
        Thread {
            try {
                val key = c.publicKeyOf(user)
                if (key == null) {
                    // No key row: plaintext shares still work, anything
                    // encrypted below stays unreadable for them - say it.
                    val keyed = row.encVersion > 0 || row.isDir
                    runOnUiThread {
                        busy = false
                        if (keyed) {
                            shareDialog = ShareDialog.NoKey(user, mask)
                        } else {
                            doSealShare(row, user, null, mask)
                        }
                    }
                    return@Thread
                }
                val known = peerFingerprint(user)
                runOnUiThread {
                    busy = false
                    when {
                        known == null ->
                            shareDialog = ShareDialog.FirstUse(user, key.fingerprint, key.public, mask)
                        known != key.fingerprint ->
                            shareDialog = ShareDialog.Changed(
                                user, known, key.fingerprint, key.public, mask
                            )
                        else -> doSealShare(row, user, key.public, mask)
                    }
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = e.message
                }
            }
        }.start()
    }

    /** Seal (5.5) and POST - the one envelope per item, plus the N4 label. */
    private fun doSealShare(row: Row, user: String, pub: String?, mask: Int) {
        val c = api ?: return
        // Names at rest (N4): a flagged plaintext file has no key to
        // wrap its label under - the server refuses that shape too.
        if (row.nameEnc != 0 && !row.isDir && row.encVersion == 0) {
            notice = "This name is flagged but the file carries no key - nothing to seal"
            return
        }
        busy = true
        notice = null
        Thread {
            try {
                var envelope: String? = null
                var label: String? = null
                if (pub != null) {
                    val rk = rootKey
                        ?: throw RuntimeException("Locked - unlock first")
                    val sealKey = Chain.shareSealValue(c, rk, row)
                    if (sealKey != null) {
                        val sealed = FxCore.eciesSeal(
                            Chain.decodeB64(pub), sealKey, row.id, user
                        )
                        envelope = java.util.Base64.getEncoder().encodeToString(sealed)
                        label = Chain.shareLabel(row, sealKey, user)
                    }
                }
                val out = c.shareBatch(row.id, user, mask, envelope, label)
                val ok = out.optJSONArray("ok") ?: JSONArray()
                val failed = out.optJSONArray("failed") ?: JSONArray()
                val detail = if (failed.length() > 0) {
                    val f = failed.optJSONObject(0)
                    val err = f?.optString("error")?.takeIf { it.isNotEmpty() }
                        ?: f?.optString("name") ?: "unknown"
                    ", ${failed.length()} failed: $err"
                } else {
                    ""
                }
                runOnUiThread {
                    busy = false
                    notice = if (ok.length() > 0) {
                        "Shared with $user$detail"
                    } else {
                        "Nothing shared$detail"
                    }
                    refreshOutgoing(c, row)
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Share failed: ${e.message}"
                }
            }
        }.start()
    }

    private fun refreshOutgoing(c: ApiClient, row: Row) {
        Thread {
            try {
                val outgoing = c.outgoingShares(row.id)
                runOnUiThread { shareOutgoing = outgoing }
            } catch (e: Throwable) {
                // the list stays as it was
            }
        }.start()
    }

    /** Revoke one of my shares (DELETE /api/shares/{id}). */
    private fun revokeShare(id: Long) {
        val c = api ?: return
        val row = shareFor ?: return
        if (busy) return
        busy = true
        Thread {
            try {
                c.revokeShare(id)
                val outgoing = c.outgoingShares(row.id)
                runOnUiThread {
                    shareOutgoing = outgoing
                    busy = false
                    notice = "Share revoked"
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Revoke failed: ${e.message}"
                }
            }
        }.start()
    }

    /** Trust on first use (DECISION 6): a hash of a published key -
     *  the one thing the web keeps in localStorage, and the app keeps
     *  in prefs. It opens nothing. */
    private fun peerFingerprint(user: String): String? = try {
        val raw = prefs.getString("peerfp", null) ?: return null
        JSONObject(raw).optString(user).takeIf { it.isNotEmpty() }
    } catch (e: Throwable) {
        null
    }

    private fun rememberPeer(user: String, fingerprint: String) {
        val obj = try {
            JSONObject(prefs.getString("peerfp", null) ?: "{}")
        } catch (e: Throwable) {
            JSONObject()
        }
        obj.put(user, fingerprint)
        prefs.edit().putString("peerfp", obj.toString()).apply()
    }

    /** The web's formatFingerprint:8-8-8-8 hex groups. */
    private fun formatFingerprint(hex: String): String {
        val s = hex.lowercase()
        return if (s.length == 32) s.chunked(8).joinToString(" ") else s
    }

    // ------------------------------------------------- device unlock (S4b)

    /** Keep the device blob after an unlock while the switch is on:
     *  {v:1, deviceKeyEnc, wrappedArk} in prefs - the web's
     *  device_unlock entry, with the device key in the Keystore.
     *  Best effort: no blob just means the pane next time. */
    private fun storeDeviceBlob(ark: ByteArray) {
        try {
            val id = myId
            if (id == -1L) return
            val deviceKey = Chain.randomBytes(32)
            val sealed = DeviceUnlock.seal(id, deviceKey) ?: return
            val wrapped = java.util.Base64.getEncoder().encodeToString(
                FxCore.wrap(deviceKey, ark, DEVICE_AAD)
            )
            val blob = JSONObject()
                .put("v", 1)
                .put("deviceKeyEnc", sealed)
                .put("wrappedArk", wrapped)
            prefs.edit().putString("device.$id", blob.toString()).apply()
        } catch (e: Throwable) {
            // no storage that works: no auto-unlock, pane stays
        }
    }

    /** Open the stored blob: Keystore, unwrap with the device AAD,
     *  sessionFromArk, share envelopes - or null on anything stale or
     *  tampered, so the passphrase pane stays the fallback exactly
     *  like the web's adoptDeviceUnlock. */
    private fun tryAdoptDevice(c: ApiClient, keys: String, userId: Long): ByteArray? {
        return try {
            val raw = prefs.getString("device.$userId", null) ?: return null
            val blob = JSONObject(raw)
            if (blob.optInt("v", 0) != 1) return null
            val deviceKey =
                DeviceUnlock.open(userId, blob.getString("deviceKeyEnc")) ?: return null
            val ark = FxCore.unwrap(deviceKey, blob.getString("wrappedArk"), DEVICE_AAD)
            val packed = FxCore.sessionFromArk(keys, ark)
            if (myUsername.isNotEmpty()) {
                Chain.openShares(c, myUsername, unpackSession(packed).pkcs8)
            }
            packed
        } catch (e: Throwable) {
            null
        }
    }

    // ---------------------------------------------------- rotate (S4c)

    /**
     * The web's rotateFileKey on a phone: fresh content key, old
     * history dropped with the old key (history=drop), then every
     * outgoing envelope re-sealed to the new key so no grant goes
     * stale (resealOutgoing).
     */
    private fun rotateFile(row: Row) {
        val c = api ?: return
        val rk = rootKey ?: return
        if (busy) return
        if (row.encVersion <= 0 || row.isDir || row.encKey == null) {
            notice = "Nothing to rotate here"
            return
        }
        busy = true
        notice = null
        Thread {
            try {
                val parentKey = Chain.keyFor(c, rk, row.parentId)
                val oldKey = FxCore.unwrapChild(parentKey, row.id, row.encKey!!)
                val container = c.download(row.id)
                val plain = FxCore.decryptBytes(row.id, oldKey, container)
                val newKey = Chain.randomBytes(32)
                val rotated = FxCore.encryptBytes(row.id, newKey, plain)
                val wrapped = FxCore.wrapChild(parentKey, row.id, newKey)
                c.putContent(
                    row.id,
                    rotated,
                    java.util.Base64.getEncoder().encodeToString(wrapped),
                    dropHistory = true
                )
                // Reseal every outgoing envelope (5.5): the raw key is
                // the same value the grantee's envelope must now carry.
                val outgoing = c.outgoingShares(row.id)
                var resealed = 0
                val failed = ArrayList<String>()
                for (s in outgoing) {
                    val pub = try {
                        c.publicKeyOf(s.username)
                    } catch (e: Throwable) {
                        null
                    }
                    if (pub == null) {
                        failed.add(s.username)
                        continue
                    }
                    try {
                        val env = java.util.Base64.getEncoder().encodeToString(
                            FxCore.eciesSeal(
                                Chain.decodeB64(pub.public), newKey, row.id, s.username
                            )
                        )
                        c.putShareEnvelope(s.id, env)
                        resealed++
                    } catch (e: Throwable) {
                        failed.add(s.username)
                    }
                }
                val failedMsg = if (failed.isEmpty()) "" else " (${failed.joinToString()} failed)"
                runOnUiThread {
                    busy = false
                    loadTree() // refreshes the row's key record
                    notice = if (outgoing.isEmpty()) {
                        "Key rotated"
                    } else {
                        "Key rotated, resealed for $resealed$failedMsg"
                    }
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Rotate failed: ${e.message}"
                }
            }
        }.start()
    }

    // ------------------------------------------------------------------- ui

    @Composable
    private fun AppUi() {
        // The header's Logout follows the step: hidden on the sign-in
        // form, present wherever a session exists to end.
        LaunchedEffect(step) {
            findViewById<TextView>(R.id.headerLogout).visibility =
                if (step == Step.LOGIN) View.GONE else View.VISIBLE
        }
        MaterialTheme(
            colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()
        ) {
            // MaterialTheme only provides colors; Surface paints them.
            // Without this the screens are transparent and the dark XML
            // window shows through under light-mode text - unreadable.
            Surface(Modifier.fillMaxSize()) {
                val sharing = shareFor
                val shown = preview
                when {
                    sharing != null -> ShareUi(sharing)
                    shown != null -> PreviewUi(shown)
                    step == Step.LOGIN -> LoginUi()
                    step == Step.PASSPHRASE -> UnlockUi()
                    else -> FilesUi()
                }
            }
        }
    }

    @Composable
    private fun LoginUi() {
        var server by remember { mutableStateOf(prefs.getString("base", "") ?: "") }
        var user by remember { mutableStateOf(prefs.getString("user", "") ?: "") }
        var password by remember { mutableStateOf("") }
        Column(
            Modifier.fillMaxSize().padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.Center
        ) {
            OutlinedTextField(
                server, { server = it },
                label = { Text("Server (https://...)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                user, { user = it },
                label = { Text("Username") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                password, { password = it },
                label = { Text("Password") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(16.dp))
            Button(
                { doLogin(server, user, password) },
                enabled = !busy && server.isNotBlank() && user.isNotBlank() && password.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (busy) {
                    CircularProgressIndicator(Modifier.height(18.dp).width(18.dp), strokeWidth = 2.dp)
                } else {
                    Text("Sign in")
                }
            }
            notice?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error)
            }
        }
    }

    @Composable
    private fun UnlockUi() {
        var secret by remember { mutableStateOf("") }
        var recovery by remember { mutableStateOf(false) }
        Column(
            Modifier.fillMaxSize().padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                if (recovery) "Lost the passphrase?"
                else "This account is encrypted."
            )
            Spacer(Modifier.height(4.dp))
            Text(
                if (recovery) {
                    "Enter the32-byte recovery key as hex (grouping is ignored)."
                } else {
                    "Enter your storage passphrase to unlock it for this session."
                },
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
            )
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                secret, { secret = it },
                label = {
                    Text(if (recovery) "Recovery key (hex)" else "Storage passphrase")
                },
                singleLine = true,
                visualTransformation = if (recovery) {
                    VisualTransformation.None
                } else {
                    PasswordVisualTransformation()
                },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(16.dp))
            Button(
                {
                    if (recovery) doRecovery(secret) else doUnlock(secret)
                },
                enabled = !busy && secret.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (busy) {
                    CircularProgressIndicator(Modifier.height(18.dp).width(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(if (recovery) "Unlock with recovery key" else "Unlock")
                }
            }
            TextButton({
                recovery = !recovery
                secret = ""
                notice = null
            }) {
                Text(
                    if (recovery) "Use the passphrase instead"
                    else "Forgot the passphrase? Use the recovery key"
                )
            }
            notice?.let {
                Text(it, color = MaterialTheme.colorScheme.error)
            }
        }
    }

    @OptIn(ExperimentalFoundationApi::class)
    @Composable
    private fun FilesUi() {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth()
                    .heightIn(min = 44.dp)
                    .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.06f))
                    .padding(horizontal = 12.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // The path bar, the web's renderBreadcrumb in kind: earlier
                // segments are links (underlined, accent-colored like the
                // web's), the current folder semibold, "›" between - and
                // never an empty strip: without crumbs the bar still says
                // "Home", exactly like the web's root view. Every color is
                // explicit here so no inherited value can make it vanish.
                Row(
                    Modifier.weight(1f)
                        .horizontalScroll(rememberScrollState()),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    val path = crumbs.ifEmpty { listOf(Crumb(null, "Home", 0, 0)) }
                    path.forEachIndexed { i, crumb ->
                        if (i > 0) {
                            Text(
                                "›",
                                fontSize = 14.sp,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
                                modifier = Modifier.padding(horizontal = 4.dp)
                            )
                        }
                        if (i == path.lastIndex) {
                            Text(
                                crumb.name,
                                maxLines = 1,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        } else {
                            TextButton({
                                if (crumb.id != parent) openFolder(crumb.id)
                            }) {
                                Text(
                                    crumb.name,
                                    maxLines = 1,
                                    fontSize = 14.sp,
                                    color = MaterialTheme.colorScheme.primary,
                                    textDecoration = TextDecoration.Underline
                                )
                            }
                        }
                    }
                }
                TextButton({ startUpload() }, enabled = !busy) { Text("Upload") }
                if (busy) {
                    CircularProgressIndicator(Modifier.width(16.dp).height(16.dp), strokeWidth = 2.dp)
                }
                // The way out sits in the XML header (headerLogout) - the
                // one element this device has always rendered.
            }
            notice?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }
            LazyColumn(Modifier.weight(1f)) {
                if (rows.isEmpty() && !busy) {
                    item {
                        Text(
                            "This folder is empty",
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 24.dp)
                        )
                    }
                }
                items(rows, key = { it.id }) { row ->
                    Row(
                        Modifier.fillMaxWidth()
                            .combinedClickable(
                                onClick = { onRow(row) },
                                onLongClick = { openShare(row) }
                            )
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(if (row.isDir) "\uD83D\uDCC1" else "\uD83D\uDCC4")
                        Spacer(Modifier.width(12.dp))
                        Column {
                            Text(row.name, maxLines = 2)
                            if (!row.isDir) {
                                Text(
                                    formatSize(row.size),
                                    fontSize = 12.sp,
                                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    /** S4a: share one row - grantee picker, fingerprint with TOFU,
     *  permissions, the existing shares with revoke, and the confirm
     *  dialogs before anything is sealed. */
    @Composable
    private fun ShareUi(row: Row) {
        var menuOpen by remember { mutableStateOf(false) }
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton({
                    shareFor = null
                    shareDialog = null
                    notice = null
                }) { Text("\u2190 Back") }
                Text(
                    "Share: ${row.name}",
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    fontWeight = FontWeight.Medium
                )
                if (busy) {
                    CircularProgressIndicator(
                        Modifier.width(16.dp).height(16.dp), strokeWidth = 2.dp
                    )
                }
            }
            Column(
                Modifier.weight(1f)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp)
            ) {
                Text("Grantee", fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                Box {
                    TextButton({ menuOpen = true }, modifier = Modifier.fillMaxWidth()) {
                        Text(shareTarget ?: "Pick an account")
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        if (shareTargets.isEmpty()) {
                            DropdownMenuItem(
                                text = { Text("No accounts yet") },
                                onClick = { menuOpen = false }
                            )
                        }
                        shareTargets.forEach { t ->
                            val label = buildString {
                                append(t.username)
                                if (t.displayName.isNotEmpty() && t.displayName != t.username) {
                                    append(" (${t.displayName})")
                                }
                                if (!t.active) append(" (inactive)")
                            }
                            DropdownMenuItem(
                                text = { Text(label) },
                                onClick = {
                                    menuOpen = false
                                    selectShareTarget(t.username)
                                }
                            )
                        }
                    }
                }
                Spacer(Modifier.height(8.dp))
                val target = shareTarget
                val key = shareKey
                when {
                    target == null -> {}
                    busy && key == null -> Text(
                        "Looking up keys...",
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                    )
                    key == null -> Text(
                        // No key row (404): plaintext shares only - the
                        // web says this out loud instead of silence.
                        "No encryption keys for $target - plaintext shares only",
                        color = MaterialTheme.colorScheme.error
                    )
                    else -> Text(
                        "Fingerprint for $target:\n${formatFingerprint(key.fingerprint)}",
                        fontSize = 14.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
                Spacer(Modifier.height(12.dp))
                Text("Permissions", fontWeight = FontWeight.SemiBold)
                permOptions.forEach { (bit, label) ->
                    Row(
                        Modifier.fillMaxWidth().clickable { togglePerm(bit) },
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(
                            checked = bit in sharePerms,
                            onCheckedChange = { togglePerm(bit) }
                        )
                        Text(label)
                    }
                }
                Spacer(Modifier.height(8.dp))
                Button(
                    { confirmShare() },
                    enabled = !busy && target != null,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Share")
                }
                Spacer(Modifier.height(16.dp))
                Text("Existing shares", fontWeight = FontWeight.SemiBold)
                if (shareOutgoing.isEmpty()) {
                    Text(
                        "None yet",
                        fontSize = 13.sp,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                    )
                }
                shareOutgoing.forEach { s ->
                    Row(
                        Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(s.username, fontSize = 15.sp)
                            Text(
                                s.permissionNames.joinToString(", "),
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                            )
                        }
                        TextButton({ revokeShare(s.id) }, enabled = !busy) {
                            Text("Revoke", color = MaterialTheme.colorScheme.error)
                        }
                    }
                }
                notice?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
                }
                Spacer(Modifier.height(16.dp))
            }
        }
        shareDialog?.let { ShareDialogUi(it, row) }
    }

    /** The two TOFU states and the web's no-key warning (app.js). */
    @Composable
    private fun ShareDialogUi(d: ShareDialog, row: Row) {
        when (d) {
            is ShareDialog.FirstUse -> AlertDialog(
                onDismissRequest = { shareDialog = null },
                title = { Text("First time with ${d.user}") },
                text = {
                    Text(
                        "Compare this fingerprint with ${d.user} out of band " +
                            "before you trust it - a stranger's key looks exactly " +
                            "like a friend's.\n\n${formatFingerprint(d.fp)}"
                    )
                },
                confirmButton = {
                    TextButton({
                        rememberPeer(d.user, d.fp)
                        shareDialog = null
                        doSealShare(row, d.user, d.pub, d.mask)
                    }) { Text("Matches - share") }
                },
                dismissButton = {
                    TextButton({ shareDialog = null }) { Text("Cancel") }
                }
            )
            is ShareDialog.Changed -> AlertDialog(
                onDismissRequest = { shareDialog = null },
                title = { Text("Fingerprint changed") },
                text = {
                    Text(
                        "The key for ${d.user} is DIFFERENT from the one you " +
                            "trusted before:\n\nwas: ${formatFingerprint(d.old)}\n" +
                            "is:  ${formatFingerprint(d.fp)}\n\nA change can mean a " +
                            "new device - or someone in between. Do not continue " +
                            "unless you can verify it out of band."
                    )
                },
                confirmButton = {
                    TextButton({
                        rememberPeer(d.user, d.fp)
                        shareDialog = null
                        doSealShare(row, d.user, d.pub, d.mask)
                    }) { Text("Verified - share anyway") }
                },
                dismissButton = {
                    TextButton({ shareDialog = null }) { Text("Cancel") }
                }
            )
            is ShareDialog.NoKey -> AlertDialog(
                onDismissRequest = { shareDialog = null },
                title = { Text("${d.user} has no keys") },
                text = {
                    Text(
                        "This account cannot read anything encrypted - a " +
                            "plaintext file or folder still shares fine, but " +
                            "encrypted content and folders would stay " +
                            "unreadable for them."
                    )
                },
                confirmButton = {
                    TextButton({
                        shareDialog = null
                        doSealShare(row, d.user, null, d.mask)
                    }) { Text("Share plaintext anyway") }
                },
                dismissButton = {
                    TextButton({ shareDialog = null }) { Text("Cancel") }
                }
            )
        }
    }

    private fun togglePerm(bit: Int) {
        sharePerms = if (bit in sharePerms) sharePerms - bit else sharePerms + bit
    }

    /** The S3b preview: a top bar with back, name and - for an
     *  encrypted file the owner holds - the S4c rotate entry. */
    @Composable
    private fun PreviewUi(p: Preview) {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton({ preview = null }) { Text("\u2190 Back") }
                Text(
                    p.row.name,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    fontWeight = FontWeight.Medium
                )
                if (p.row.encVersion > 0 && !p.row.isDir && p.row.ownerId == myId) {
                    TextButton({ rotateConfirm = true }, enabled = !busy) {
                        Text("Rotate")
                    }
                }
                if (busy) {
                    CircularProgressIndicator(
                        Modifier.width(16.dp).height(16.dp), strokeWidth = 2.dp
                    )
                }
            }
            when (p.kind) {
                Kind.IMAGE -> Box(
                    Modifier.fillMaxSize().padding(8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Image(
                        bitmap = p.bitmap!!.asImageBitmap(),
                        contentDescription = p.row.name,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Fit
                    )
                }
                else -> SelectionContainer {
                    Text(
                        p.text ?: "",
                        modifier = Modifier.fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .padding(16.dp),
                        fontSize = 14.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
        }
        if (rotateConfirm) {
            AlertDialog(
                onDismissRequest = { rotateConfirm = false },
                title = { Text("Rotate the key?") },
                text = {
                    Text(
                        "${p.row.name} gets a fresh content key and the " +
                            "old versions drop with the old one - that " +
                            "history cannot come back. Outgoing shares " +
                            "are re-sealed to the new key so nobody's " +
                            "grant goes stale."
                    )
                },
                confirmButton = {
                    TextButton({
                        rotateConfirm = false
                        rotateFile(p.row)
                    }) { Text("Rotate") }
                },
                dismissButton = {
                    TextButton({ rotateConfirm = false }) { Text("Cancel") }
                }
            )
        }
    }

    private fun formatSize(bytes: Long): String = when {
        bytes >= 1_073_741_824L -> "%.1f GB".format(bytes / 1_073_741_824.0)
        bytes >= 1_048_576L -> "%.1f MB".format(bytes / 1_048_576.0)
        bytes >= 1_024L -> "%.1f KB".format(bytes / 1_024.0)
        else -> "$bytes B"
    }
}
