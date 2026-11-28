package de.frischux.fxcloud

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.graphics.pdf.PdfRenderer
import android.media.ExifInterface
import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.text.Html
import android.text.method.LinkMovementMethod
import android.view.View
import android.webkit.WebView
import android.widget.ImageView
import android.widget.PopupMenu
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.detectDragGestures
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
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
import androidx.compose.material3.Switch
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.io.ByteArrayInputStream
import java.io.File
import java.util.Locale
import kotlin.math.abs
import kotlinx.coroutines.delay
import org.json.JSONArray
import org.json.JSONObject

/** The three stops of S2: sign in, unlock (encrypted accounts), browse. */
private enum class Step { LOGIN, PASSPHRASE, FILES }

/** Pre-filled on the login form (changeable) - the instance this app
 *  was built for; any other fxcloud address works the same. */
private const val DEFAULT_SERVER = "https://fxcloud.frischux.de"

/** What a preview can show in v1 (S3b): image and text, nothing else. */
private enum class Kind { IMAGE, TEXT, PDF, OTHER }

/** What the plus-menu in the path bar creates (S5 parity). */
private enum class CreateKind { FOLDER, FILE }

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
 *  the bar), decoded bitmap, text or PDF pages, held in memory. */
private class Preview(
    val row: Row,
    val kind: Kind,
    val bitmap: Bitmap? = null,
    val text: String? = null,
    val pages: List<Bitmap>? = null,
    val pdfTotal: Int =0,
    /** False for a version stand: rotation acts on the current file. */
    val allowRotate: Boolean = true
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

/** A copy/move in flight: the rows, the mode, and the folder to come
 *  back to when it is done or cancelled. */
private class Transfer(val rows: List<Row>, val copy: Boolean, val from: Long?)

/**
 * S2: sign in against a live instance, unlock the account material, list
 * the tree with its breadcrumb and decrypt names-at-rest through JNI
 * (concepts/android.md A4-A6). The XML frame is the S1 shape that proved
 * itself on the device; the screens below the header are Compose (A2).
 */
// FragmentActivity, not ComponentActivity: androidx.biometric's
// prompt takes a FragmentActivity - which is one, so Compose, the
// activity-result APIs and the back dispatcher are unaffected.
class MainActivity : FragmentActivity() {

    private val prefs by lazy { getSharedPreferences("fxcloud", MODE_PRIVATE) }

    /** Set by login/restore; every call runs on the caller's thread. */
    @Volatile private var api: ApiClient? = null
    @Volatile private var keysJson: String? = null
    @Volatile private var myId: Long = -1

    /** The grantee half of every share AAD (N4) - from /api/me. */
    @Volatile private var myUsername: String = ""

    /** The account's auto-unlock switch (server-side, /api/me). */
    @Volatile private var autoUnlock: Boolean = false

    /** Fingerprint unlock (concepts/android.md): a biometric blob
     *  exists for this account - Compose reads it on the settings
     *  switch and the passphrase pane; written on the UI thread. */
    private var bioUnlock by mutableStateOf(false)

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
    /** The open preview - and its load generation. Every write of
     *  null is a close (←, system back, or another overlay taking
     *  over), which invalidates in-flight loads: they must never
     *  resurrect a preview the user has already left, and a newer
     *  load must never be overwritten by an older one that lands
     *  late. */
    private val previewState = mutableStateOf<Preview?>(null)
    private var previewLoadSeq = 0
    private var previewLoads = 0
    private var preview: Preview?
        get() = previewState.value
        set(value) {
            if (value == null) previewLoadSeq++
            previewState.value = value
        }

    /** The S4c confirmation before a key rotation drops history. */
    private var rotateConfirm by mutableStateOf(false)

    /** The system picker for S3c: any file, read through the content
     *  resolver - the picker's URI needs no storage permission. */
    private val pickFile =
        registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
            if (uri != null) doUpload(uri)
        }

    /** The folder picker behind "Upload folder": the granted tree is
     *  walked right away, no persisted permission needed for that. */
    private val pickFolder =
        registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            if (uri != null) doUploadTree(uri)
        }

    // ------------------------------------------------------------ sharing (S4a)

    /** Non-null replaces the list area with the share screen (one row
     *  or a selection). */
    private var shareFor by mutableStateOf<List<Row>?>(null)
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

    // ------------------------------------------------- row actions (S5 early)

    /** The row whose ⋮ menu is open. */
    private var rowMenu by mutableStateOf<Row?>(null)

    /** Long-press multi-select: the ids selected in the listing. */
    private var selection by mutableStateOf<Set<Long>>(emptySet())

    /** Rows waiting for the trash confirmation. */
    private var deleteConfirm by mutableStateOf<List<Row>?>(null)

    /** Non-null: the listing is picking a destination for these rows. */
    private var transfer by mutableStateOf<Transfer?>(null)

    private fun selectedRows(): List<Row> = rows.filter { it.id in selection }

    private fun toggleSelect(id: Long) {
        selection = if (id in selection) selection - id else selection + id
    }

    // -------------------------------------------------------------- trash (S5a)

    /** Non-null: the trash overlay is up. */
    private var trashOpen by mutableStateOf(false)
    private var trashItems by mutableStateOf<List<ApiClient.Trashed>>(emptyList())
    private var purgeConfirm by mutableStateOf<ApiClient.Trashed?>(null)
    private var emptyConfirm by mutableStateOf(false)

    /** The help overlay: the server's guide in a script-less WebView
     *  (the page ships without scripts, ui.rs), with its own back
     *  stack under the shared one. */
    private var helpOpen by mutableStateOf(false)
    private var helpUrl by mutableStateOf("")
    private var helpWeb by mutableStateOf<WebView?>(null)

    // --------------------------------------------------------- settings (S5b)

    /** Non-null: the settings overlay is up. */
    private var settingsOpen by mutableStateOf(false)

    /** Non-null: the versions overlay of that file is up. */
    private var versionsOpen by mutableStateOf(false)
    private var versionsFor by mutableStateOf<Row?>(null)
    private var versionItems by mutableStateOf<List<ApiClient.Version>>(emptyList())
    private var deleteVersionConfirm by mutableStateOf<ApiClient.Version?>(null)

    /** Non-null: the text/markdown editor overlay of that file is up. */
    private var editorRow by mutableStateOf<Row?>(null)
    private var editorText by mutableStateOf(TextFieldValue(""))
    private var editorBaseline by mutableStateOf("")
    private var editorMd by mutableStateOf(false)
    private var editorMdPane by mutableStateOf(false)
    private var editorStatus by mutableStateOf<String?>(null)
    private var editorStatusError by mutableStateOf(false)
    /** What the next save must do: reuse the row's key, promote a
     *  plaintext row under a keyed folder, or write plaintext. */
    private var editorEncrypted by mutableStateOf(false)
    private var editorEncKey by mutableStateOf<String?>(null)
    private var editorCloseConfirm by mutableStateOf(false)

    /** "system", "light" or "dark" - what the server knows, applied
     *  over the system default (the web's theme section). */
    private var themeMode by mutableStateOf("system")

    /** Dot-entries hidden by default - the web's rule (its
     *  `fxcloud.showHidden`), a display preference in prefs. */
    private var showHidden by mutableStateOf(false)

    /** The account's display name and the field buffer for the form. */
    private var myDisplayName by mutableStateOf("")
    private var settingsName by mutableStateOf("")

    /** Non-null: the create-name dialog (folder or file). */
    private var createDialog by mutableStateOf<CreateKind?>(null)
    private var createName by mutableStateOf("")

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
        showHidden = prefs.getBoolean("showhidden", false)
        try {
            setContentView(R.layout.activity_main)
            // The header mirrors the web's topbar: the trash as a
            // one-tap icon, the rest behind the account name.
            findViewById<ImageView>(R.id.headerTrash).setOnClickListener { openTrash() }
            findViewById<TextView>(R.id.headerUser).setOnClickListener { showUserMenu(it) }
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
                    bioUnlock = prefs.getString("biodevice.${me.id}", null) != null
                    themeMode = prefs.getString("thememode", null) ?: me.theme.ifEmpty { "system" }
                    myDisplayName = me.displayName
                    settingsName = me.displayName
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
                if (reply.code != 200) throw RuntimeException(serverReason(reply, "Sign-in failed"))
                finishLogin(c, server, user, password)
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = e.message ?: "Sign-in failed"
                }
            }
        }.start()
    }

    /** Sign up from the login page (the web's register tab): an active
     *  account comes back with its session cookie, a pending one with
     * 202 and no cookie - which then simply says so. */
    /** The server's own reason for a refusal (a rate limit carries
     *  its retry clock in there); the status code as the fallback. */
    private fun serverReason(reply: ApiClient.Reply, fallback: String): String {
        val msg = try {
            JSONObject(reply.body).optString("error")
        } catch (e: Throwable) {
            ""
        }
        return if (msg.isNotEmpty()) msg else "$fallback (${reply.code})"
    }

    private fun doRegister(server: String, user: String, password: String, displayName: String) {
        busy = true
        notice = null
        Thread {
            try {
                val c = ApiClient(server)
                val reply = c.register(user, password, displayName.ifBlank { null })
                if (reply.code == 202) {
                    runOnUiThread {
                        busy = false
                        notice = "Account created. An administrator has to activate it before you can sign in."
                    }
                    return@Thread
                }
                if (reply.code != 200) throw RuntimeException(serverReason(reply, "Sign-up failed"))
                finishLogin(c, server, user, password)
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = e.message ?: "Sign-up failed"
                }
            }
        }.start()
    }

    /** Everything after a session exists: persist it, learn who I am,
     *  then device-blob, passphrase pane or list - the same three-way
     *  the restore path takes (the web adopts the device blob after a
     *  fresh login too). */
    private fun finishLogin(c: ApiClient, server: String, user: String, password: String) {
        prefs.edit()
            .putString("base", ApiClient.normalizeBaseUrl(server))
            .putString("user", user)
            .putString("session", c.sessionCookie)
            .apply()
        val me = c.me()
        val keys = c.keysOrNull()
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
            bioUnlock = prefs.getString("biodevice.${me.id}", null) != null
            themeMode = prefs.getString("thememode", null) ?: me.theme.ifEmpty { "system" }
            myDisplayName = me.displayName
            settingsName = me.displayName
            keysJson = keys
            busy = false
            history.clear()
            when {
                adopted != null -> {
                    packedSession = adopted
                    rootKey = unpackSession(adopted).root
                    step = Step.FILES
                    loadTree()
                }
                keys == null -> {
                    step = Step.FILES
                    loadTree()
                }
                // One event (DECISION 3): the password that just signed
                // in unlocks right away; a separate storage secret fails
                // here and lands on the pane - the fallback, not an error.
                else -> unlockWith(password, false) { step = Step.PASSPHRASE }
            }
        }
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

    private fun logout() {
        prefs.edit().remove("session").apply()
        Chain.clear()
        packedSession = null
        bioUnlock = false
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
        rowMenu = null
        selection = emptySet()
        deleteConfirm = null
        createDialog = null
        transfer = null
        trashOpen = false
        trashItems = emptyList()
        purgeConfirm = null
        emptyConfirm = false
        settingsOpen = false
        helpOpen = false
        helpUrl = ""
        helpWeb = null
        versionsOpen = false
        versionsFor = null
        versionItems = emptyList()
        deleteVersionConfirm = null
        editorRow = null
        editorText = TextFieldValue("")
        editorBaseline = ""
        editorStatus = null
        editorStatusError = false
        editorCloseConfirm = false
        editorMd = false
        editorMdPane = false
        editorEncrypted = false
        editorEncKey = null
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
            // Dialogs first (they usually eat the press themselves),
            // then the overlays, an active selection or a destination
            // pick - and only then the tree walks up.
            purgeConfirm != null -> purgeConfirm = null
            emptyConfirm -> emptyConfirm = false
            deleteConfirm != null -> deleteConfirm = null
            deleteVersionConfirm != null -> deleteVersionConfirm = null
            editorCloseConfirm -> editorCloseConfirm = false
            rowMenu != null -> rowMenu = null
            createDialog != null -> createDialog = null
            trashOpen -> closeTrash()
            helpOpen -> leaveHelp()
            settingsOpen -> closeSettings()
            shareFor != null -> {
                shareFor = null
                shareDialog = null
                notice = null
            }
            preview != null -> {
                preview = null
                rotateConfirm = false
            }
            // The editor guards its own text; below it, a version's
            // preview still returns to the list it came from.
            editorRow != null -> requestEditorClose()
            versionsOpen -> closeVersions()
            selection.isNotEmpty() -> selection = emptySet()
            transfer != null -> cancelTransfer()
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
        // A tap while selecting toggles; while picking a destination it
        // only descends into folders - no preview, no share mid-flow.
        if (selection.isNotEmpty()) {
            toggleSelect(row.id)
            return
        }
        if (transfer != null) {
            if (row.isDir) openFolder(row.id)
            return
        }
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
        if (ext == "pdf") return Kind.PDF
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
    /** The plaintext behind a row's bytes: the content key unwrapped
     *  under the parent's (the S3b walk). Throws notice-friendly
     *  errors when locked or when the row carries no key record. */
    private fun decryptBody(c: ApiClient, row: Row, raw: ByteArray): ByteArray {
        val rk = rootKey ?: throw RuntimeException("Locked - unlock first")
        val encKey = row.encKey ?: throw RuntimeException("This row carries no key record")
        val parentKey = Chain.keyFor(c, rk, row.parentId)
        val contentKey = FxCore.unwrapChild(parentKey, row.id, encKey)
        return FxCore.decryptBytes(row.id, contentKey, raw)
    }

    private fun loadPreview(row: Row, versionId: Long? = null, versionEnc: Int = 0) {
        val c = api ?: return
        val kind = previewKind(row.name, row.mime)
        if (kind == Kind.OTHER) {
            val ext = row.name.substringAfterLast('.', "").uppercase()
            notice = "$ext preview comes later - image, text and PDF open today"
            return
        }
        busy = true
        notice = null
        previewLoads++
        val seq = ++previewLoadSeq
        Thread {
            try {
                val raw = if (versionId != null) {
                    c.downloadVersion(row.id, versionId)
                } else {
                    c.download(row.id)
                }
                if (raw.size > 50_000_000) {
                    throw RuntimeException("Too large to preview (${raw.size / 1_000_000} MB)")
                }
                // A version carries its own enc_version: a save from the
                // plaintext era stays plaintext even if today's row is
                // encrypted (the server's rule for version downloads).
                val encrypted =
                    if (versionId != null) versionEnc > 0 else row.encVersion > 0
                val content = if (encrypted) decryptBody(c, row, raw) else raw
                val shown = when (kind) {
                    Kind.IMAGE -> {
                        val bitmap = decodeImage(content)
                            ?: throw RuntimeException("This image cannot be displayed")
                        Preview(row, kind, bitmap = bitmap, allowRotate = versionId == null)
                    }
                    Kind.PDF -> {
                        val (pages, total) = renderPdf(content)
                        if (pages.isEmpty()) {
                            throw RuntimeException("This PDF cannot be displayed")
                        }
                        Preview(
                            row, kind, pages = pages, pdfTotal = total,
                            allowRotate = versionId == null
                        )
                    }
                    else -> {
                        if (content.size > 4_000_000) {
                            throw RuntimeException(
                                "Text too large to display (${content.size / 1_000} KB)"
                            )
                        }
                        Preview(
                            row, kind, text = String(content, Charsets.UTF_8),
                            allowRotate = versionId == null
                        )
                    }
                }
                runOnUiThread {
                    previewLoads--
                    if (seq == previewLoadSeq) preview = shown
                    // Only the last load in flight owns the busy flag;
                    // a newer one keeps it until it lands.
                    if (previewLoads <= 0) busy = false
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    previewLoads--
                    if (seq == previewLoadSeq) {
                        notice = "Preview failed: ${e.message}"
                    }
                    if (previewLoads <= 0) busy = false
                }
            }
        }.start()
    }

    /** One step through the folder's gallery - the web's arrow
     *  buttons as a gesture: every previewable entry in tree order,
     *  no wrap at the ends. A version stand is history, not part of
     *  a gallery, so it never steps. */
    private fun swipePreview(step: Int) {
        val current = preview ?: return
        if (!current.allowRotate) return
        val gallery = rows.filter {
            !it.isDir && previewKind(it.name, it.mime) != Kind.OTHER &&
                (showHidden || !it.name.startsWith("."))
        }
        val index = gallery.indexOfFirst { it.id == current.row.id }
        if (index < 0) return
        val target = gallery.getOrNull(index + step) ?: return
        loadPreview(target)
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

    /**
     * Render a PDF to page bitmaps with the platform's PdfRenderer -
     * no dependency to add (S5: the encrypted-account PDF gap). Bounded
     * on purpose:15 pages at800px width, a longer document says so
     * instead of eating memory. Explicit closes everywhere: PdfRenderer
     * only implements AutoCloseable from API29 and this app supports26.
     */
    private fun renderPdf(bytes: ByteArray): Pair<List<Bitmap>, Int> {
        val file = File(cacheDir, "preview.pdf")
        try {
            file.writeBytes(bytes)
            val pfd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
            val renderer = PdfRenderer(pfd)
            try {
                val total = renderer.pageCount
                val take = minOf(total,15)
                val out = ArrayList<Bitmap>(take)
                for (i in 0 until take) {
                    val page = renderer.openPage(i)
                    try {
                        val width =800
                        val height = ((page.height.toFloat() / page.width) * width)
                            .toInt().coerceAtLeast(1)
                        val bmp = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
                        page.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                        out.add(bmp)
                    } finally {
                        page.close()
                    }
                }
                return out to total
            } finally {
                renderer.close()
                pfd.close()
            }
        } finally {
            file.delete()
        }
    }

    // ------------------------------------------------------------- upload (S3c)

    private fun startUpload() {
        if (busy) return
        pickFile.launch("*/*")
    }

    private fun startFolderUpload() {
        if (busy) return
        pickFolder.launch(null)
    }

    /**
     * The S3c flow, mirrored from app.js/fxenc.js: create the row (a
     * random server-meaningless name under a names_enc folder, then
     * rename to the id-bound blob - N3/N5), give a recordless folder
     * its record (ensureChainKey), fresh file key, encrypt, PUT the
     * container. A failure after the row exists discards it, so no
     * half-written or plaintext leftover stays behind. Both upload
     * paths - one file and a whole tree - end here.
     */
    private fun uploadOne(
        c: ApiClient,
        target: Long?,
        name: String,
        bytes: ByteArray,
        namesEnc: Boolean
    ) {
        val rk = rootKey
        val parentKey = if (rk == null) null else Chain.ensureKey(c, rk, target)
        val temp = if (namesEnc) {
            "n" + java.util.Base64.getUrlEncoder()
                .encodeToString(Chain.randomBytes(16))
        } else {
            null
        }
        val id = c.createFile(target, temp ?: name)
        try {
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
        } catch (e: Throwable) {
            c.discard(id)
            throw e
        }
    }

    private fun doUpload(uri: Uri) {
        val c = api ?: return
        if (busy) return
        val target = parent
        val namesEnc = rootKey != null && crumbs.lastOrNull()?.namesEnc == 1
        busy = true
        notice = null
        Thread {
            try {
                val name = queryName(uri) ?: "upload.bin"
                val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                    ?: throw RuntimeException("Cannot read the selected file")
                if (bytes.size > 50_000_000) {
                    throw RuntimeException(
                        "Uploads up to50 MB for now (${bytes.size / 1_000_000} MB)"
                    )
                }
                uploadOne(c, target, name, bytes, namesEnc)
                runOnUiThread {
                    busy = false
                    loadTree() // clears the notice; set it after
                    notice = "Uploaded $name"
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Upload failed: ${e.message}"
                }
            }
        }.start()
    }

    /**
     * The folder upload: SAF hands over the picked tree,
     * DocumentsContract walks it (no dependency beyond the platform),
     * folders are created on the way - they inherit names_enc from
     * their parent, so one value covers the whole walk - and every
     * file ends in uploadOne. One unreadable entry stops the walk
     * honestly: what was uploaded stays, the message says how far it
     * got.
     */
    private fun doUploadTree(treeUri: Uri) {
        val c = api ?: return
        if (busy) return
        val target = parent
        val namesEnc = rootKey != null && crumbs.lastOrNull()?.namesEnc == 1
        busy = true
        notice = null
        Thread {
            var done = 0
            try {
                val resolver = contentResolver
                fun walk(docId: String, dest: Long?) {
                    val children =
                        DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, docId)
                    resolver.query(
                        children,
                        arrayOf(
                            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                            DocumentsContract.Document.COLUMN_MIME_TYPE
                        ),
                        null, null, null
                    )?.use { cursor ->
                        while (cursor.moveToNext()) {
                            val childId = cursor.getString(0)
                            val name = cursor.getString(1)
                            val mime = cursor.getString(2)
                            if (name == null) continue
                            if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                                walk(childId, c.createFolder(dest, name))
                            } else {
                                val childUri = DocumentsContract
                                    .buildDocumentUriUsingTree(treeUri, childId)
                                val bytes = resolver.openInputStream(childUri)
                                    ?.use { it.readBytes() }
                                    ?: throw RuntimeException("Cannot read $name")
                                if (bytes.size > 50_000_000) {
                                    throw RuntimeException(
                                        "$name is too large (${bytes.size / 1_000_000} MB)"
                                    )
                                }
                                uploadOne(c, dest, name, bytes, namesEnc)
                                done++
                                runOnUiThread { notice = "Uploading $done files..." }
                            }
                        }
                    }
                }
                walk(DocumentsContract.getTreeDocumentId(treeUri), target)
                runOnUiThread {
                    busy = false
                    loadTree() // clears the notice; set it after
                    notice = "Uploaded $done files"
                }
            } catch (e: Throwable) {
                val soFar = done
                runOnUiThread {
                    busy = false
                    notice = if (soFar > 0) {
                        "Upload stopped after $soFar files: ${e.message}"
                    } else {
                        "Upload failed: ${e.message}"
                    }
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

    /** Open the share screen for one row or a selection (the row menu
     *  and the selection bar both land here). */
    private fun openShare(targets: List<Row>) {
        val c = api ?: return
        if (busy || targets.isEmpty()) return
        shareFor = targets
        shareTarget = null
        shareKey = null
        sharePerms = setOf(1, 2, 4, 8, 16)
        shareDialog = null
        selection = emptySet()
        busy = true
        notice = null
        Thread {
            try {
                val users = c.users()
                // Existing shares only make sense item by item, like the
                // web's bulk selection says.
                val outgoing =
                    if (targets.size == 1) c.outgoingShares(targets[0].id) else emptyList()
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
        val rows = shareFor ?: return
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
                    val keyed = rows.any { it.encVersion > 0 || it.isDir }
                    runOnUiThread {
                        busy = false
                        if (keyed) {
                            shareDialog = ShareDialog.NoKey(user, mask)
                        } else {
                            doSealShare(rows, user, null, mask)
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
                        else -> doSealShare(rows, user, key.public, mask)
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

    /** Seal (5.5) and POST - one envelope per item, plus the N4 label
     *  per flagged row; a single request for the whole selection. */
    private fun doSealShare(rows: List<Row>, user: String, pub: String?, mask: Int) {
        val c = api ?: return
        // Names at rest (N4): a flagged plaintext file has no key to
        // wrap its label under - the server refuses that shape too.
        val bareFlagged = rows.filter { it.nameEnc != 0 && !it.isDir && it.encVersion == 0 }
        if (bareFlagged.isNotEmpty()) {
            notice = "A flagged name on a plaintext file - there is nothing to seal"
            return
        }
        busy = true
        notice = null
        Thread {
            try {
                val items = ArrayList<ApiClient.ShareItem>()
                if (pub != null) {
                    val rk = rootKey
                        ?: throw RuntimeException("Locked - unlock first")
                    for (r in rows) {
                        val sealKey = Chain.shareSealValue(c, rk, r)
                        var envelope: String? = null
                        var label: String? = null
                        if (sealKey != null) {
                            val sealed = FxCore.eciesSeal(
                                Chain.decodeB64(pub), sealKey, r.id, user
                            )
                            envelope =
                                java.util.Base64.getEncoder().encodeToString(sealed)
                            label = Chain.shareLabel(r, sealKey, user)
                        }
                        items.add(ApiClient.ShareItem(r.id, envelope, label))
                    }
                } else {
                    // No keys: plaintext items go through as they are.
                    for (r in rows) items.add(ApiClient.ShareItem(r.id, null, null))
                }
                val out = c.shareBatch(items, user, mask)
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
                val single = rows.singleOrNull()
                runOnUiThread {
                    busy = false
                    notice = if (ok.length() > 0) {
                        "Shared with $user$detail"
                    } else {
                        "Nothing shared$detail"
                    }
                    if (single != null) refreshOutgoing(c, single)
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
        // The list only exists for a single item (like the web's bulk
        // selection says), so refresh against that row.
        val row = shareFor?.singleOrNull() ?: return
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

    // ------------------------------------------------- row actions (S5 early)

    /** The ⋮ menu of one row: share, copy, move, delete. */
    @Composable
    private fun RowMenuUi(row: Row) {
        AlertDialog(
            onDismissRequest = { rowMenu = null },
            title = { Text(row.name, maxLines = 2) },
            text = {
                Column {
                    ActionRow("Share") {
                        rowMenu = null
                        openShare(listOf(row))
                    }
                    if (!row.isDir) {
                        ActionRow("Versions") {
                            rowMenu = null
                            openVersions(row)
                        }
                    }
                    ActionRow("Copy") {
                        rowMenu = null
                        startTransfer(listOf(row), copy = true)
                    }
                    ActionRow("Move") {
                        rowMenu = null
                        startTransfer(listOf(row), copy = false)
                    }
                    ActionRow("Delete", danger = true) {
                        rowMenu = null
                        deleteConfirm = listOf(row)
                    }
                }
            },
            confirmButton = {
                TextButton({ rowMenu = null }) { Text("Close") }
            }
        )
    }

    @Composable
    private fun ActionRow(label: String, danger: Boolean = false, onClick: () -> Unit) {
        Text(
            label,
            color = if (danger) MaterialTheme.colorScheme.error
            else MaterialTheme.colorScheme.onSurface,
            fontSize = 16.sp,
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onClick)
                .padding(vertical = 12.dp)
        )
    }

    /** The selection bar: count plus the same actions in a ⋮ menu. */
    @Composable
    private fun SelectionActions() {
        var menuOpen by remember { mutableStateOf(false) }
        Text(
            "${selection.size} selected",
            fontSize = 13.sp,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f),
            modifier = Modifier.padding(end = 4.dp)
        )
        Box {
            TextButton({ menuOpen = true }) { Text("\u22EE", fontSize = 18.sp) }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                val targets = selectedRows()
                DropdownMenuItem(
                    text = { Text("Share") },
                    onClick = { menuOpen = false; openShare(targets) }
                )
                DropdownMenuItem(
                    text = { Text("Copy") },
                    onClick = { menuOpen = false; startTransfer(targets, copy = true) }
                )
                DropdownMenuItem(
                    text = { Text("Move") },
                    onClick = { menuOpen = false; startTransfer(targets, copy = false) }
                )
                DropdownMenuItem(
                    text = { Text("Delete", color = MaterialTheme.colorScheme.error) },
                    onClick = { menuOpen = false; deleteConfirm = targets }
                )
            }
        }
    }

    /** The confirmation before anything goes to the trash. */
    @Composable
    private fun DeleteUi(items: List<Row>) {
        val n = items.size
        AlertDialog(
            onDismissRequest = { deleteConfirm = null },
            title = {
                Text(if (n == 1) "Move to trash?" else "Move $n items to the trash?")
            },
            text = {
                Text(
                    if (n == 1) {
                        "The file lands in the trash, restorable until it is " +
                            "purged - the web shows the trash view."
                    } else {
                        "The selection lands in the trash, restorable until " +
                            "it is purged."
                    }
                )
            },
            confirmButton = {
                TextButton({
                    deleteConfirm = null
                    doTrash(items)
                }) {
                    Text(
                        if (n == 1) "Move to trash" else "Move $n to trash",
                        color = MaterialTheme.colorScheme.error
                    )
                }
            },
            dismissButton = {
                TextButton({ deleteConfirm = null }) { Text("Cancel") }
            }
        )
    }

    private fun doTrash(items: List<Row>) {
        val c = api ?: return
        if (busy) return
        selection = emptySet()
        busy = true
        notice = null
        Thread {
            try {
                val out = c.trash(items.map { it.id })
                val failed = out.optJSONArray("failed")
                val failMsg =
                    if (failed != null && failed.length() > 0) ", ${failed.length()} failed" else ""
                runOnUiThread {
                    busy = false
                    loadTree()
                    notice = (if (items.size == 1) {
                        "Moved to the trash"
                    } else {
                        "Moved ${items.size} items to the trash"
                    }) + failMsg
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Delete failed: ${e.message}"
                }
            }
        }.start()
    }

    /** Copy/move: the listing becomes the destination picker (the web's
     *  transfer dialog, as a screen); Back cancels, the source folder
     *  is where the flow returns. */
    private fun startTransfer(rows: List<Row>, copy: Boolean) {
        if (busy || rows.isEmpty()) return
        selection = emptySet()
        rowMenu = null
        transfer = Transfer(rows, copy, parent)
        parent = null
        loadTree()
    }

    private fun cancelTransfer() {
        val from = transfer?.from
        transfer = null
        parent = from
        loadTree()
    }

    private fun executeTransfer() {
        val t = transfer ?: return
        val c = api ?: return
        if (busy) return
        val dest = parent // the folder the picker stands in
        busy = true
        notice = null
        Thread {
            try {
                val out = c.transfer(t.copy, t.rows.map { it.id }, dest)
                val failed = out.optJSONArray("failed")
                val failMsg =
                    if (failed != null && failed.length() > 0) ", ${failed.length()} failed" else ""
                val verb = if (t.copy) "Copied" else "Moved"
                val what = if (t.rows.size == 1) "1 item" else "${t.rows.size} items"
                runOnUiThread {
                    busy = false
                    transfer = null
                    parent = t.from
                    loadTree()
                    notice = "$verb $what$failMsg"
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = (if (t.copy) "Copy failed: " else "Move failed: ") + e.message
                }
            }
        }.start()
    }

    /** Create an empty folder or file (the web's newFolder/newFile):
     *  names-at-rest get the temp+rename dance, an encrypted file gets
     *  an empty FXE1 container right away - encrypted from its first
     *  second, exactly like the web's writeText with "". */
    private fun createRow(kind: CreateKind, name: String) {
        val c = api ?: return
        if (busy) return
        val target = parent
        val namesEnc = rootKey != null && crumbs.lastOrNull()?.namesEnc == 1
        val needsKey = namesEnc || kind == CreateKind.FILE
        busy = true
        notice = null
        Thread {
            var createdId: Long? = null
            try {
                val rk = rootKey
                val parentKey =
                    if (needsKey && rk != null) Chain.ensureKey(c, rk, target) else null
                val temp = if (namesEnc) {
                    "n" + java.util.Base64.getUrlEncoder()
                        .encodeToString(Chain.randomBytes(16))
                } else {
                    null
                }
                val id = if (kind == CreateKind.FOLDER) {
                    c.createFolder(target, temp ?: name)
                } else {
                    c.createFile(target, temp ?: name)
                }
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
                if (kind == CreateKind.FILE) {
                    if (parentKey != null) {
                        val fileKey = Chain.randomBytes(32)
                        val wrappedKey = FxCore.wrapChild(parentKey, id, fileKey)
                        val container = FxCore.encryptBytes(id, fileKey, ByteArray(0))
                        c.putContent(
                            id, container,
                            java.util.Base64.getEncoder().encodeToString(wrappedKey)
                        )
                    } else {
                        c.putContent(id, ByteArray(0), null)
                    }
                }
                runOnUiThread {
                    busy = false
                    loadTree()
                    notice = "Created $name"
                }
            } catch (e: Throwable) {
                createdId?.let { c.discard(it) }
                runOnUiThread {
                    busy = false
                    notice = "Create failed: ${e.message}"
                }
            }
        }.start()
    }

    /** The "＋" in the path bar: the web's toolbar trio as one menu. */
    @Composable
    private fun CreateMenu() {
        var open by remember { mutableStateOf(false) }
        Box {
            TextButton({ open = true }, enabled = !busy) { Text("+") }
            DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
                DropdownMenuItem(
                    text = { Text("New folder") },
                    onClick = {
                        open = false
                        createName = ""
                        createDialog = CreateKind.FOLDER
                    }
                )
                DropdownMenuItem(
                    text = { Text("New file") },
                    onClick = {
                        open = false
                        createName = ""
                        createDialog = CreateKind.FILE
                    }
                )
                DropdownMenuItem(
                    text = { Text("Upload") },
                    onClick = {
                        open = false
                        startUpload()
                    }
                )
                DropdownMenuItem(
                    text = { Text("Upload folder") },
                    onClick = {
                        open = false
                        startFolderUpload()
                    }
                )
            }
        }
    }

    /** The name prompt for the create menu. */
    @Composable
    private fun CreateUi(kind: CreateKind) {
        AlertDialog(
            onDismissRequest = { createDialog = null },
            title = { Text(if (kind == CreateKind.FOLDER) "New folder" else "New file") },
            text = {
                OutlinedTextField(
                    createName, { createName = it },
                    label = {
                        Text(if (kind == CreateKind.FOLDER) "Folder name" else "File name")
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            },
            confirmButton = {
                TextButton({
                    val name = createName.trim()
                    if (name.isNotBlank()) {
                        createDialog = null
                        createRow(kind, name)
                    }
                }) { Text("Create") }
            },
            dismissButton = {
                TextButton({ createDialog = null }) { Text("Cancel") }
            }
        )
    }

    // --------------------------------------------------------- settings (S5b)

    /** The header's Settings: one overlay at a time, form buffered. */
    private fun openSettings() {
        if (busy) return
        shareFor = null
        shareDialog = null
        preview = null
        rotateConfirm = false
        rowMenu = null
        deleteConfirm = null
        selection = emptySet()
        transfer = null
        trashOpen = false
        trashItems = emptyList()
        purgeConfirm = null
        emptyConfirm = false
        settingsName = myDisplayName
        notice = null
        settingsOpen = true
    }

    private fun closeSettings() {
        settingsOpen = false
        notice = null
    }

    /** One PUT /api/me; the response refreshes every local copy and
     *  `onDone` runs on the UI thread for the side effects. */
    private fun saveMe(
        message: String,
        call: (ApiClient) -> ApiClient.Me,
        onDone: ((ApiClient.Me) -> Unit)? = null
    ) {
        val c = api ?: return
        if (busy) return
        busy = true
        notice = null
        Thread {
            try {
                val updated = call(c)
                runOnUiThread {
                    busy = false
                    myUsername = updated.username
                    autoUnlock = updated.autoUnlock
                    myDisplayName = updated.displayName
                    themeMode = updated.theme.ifEmpty { "system" }
                    onDone?.invoke(updated)
                    notice = message
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = e.message
                }
            }
        }.start()
    }

    private fun saveDisplayName(name: String) =
        // The call lambda explicit: a trailing one would bind to onDone.
        saveMe("Display name saved", { it.updateMe(displayName = name) })

    /** The phone's theme is the phone's choice (the web keeps its own
     *  per account, and the server knows only light|dark): three modes
     *  in prefs, "system" never travels. */
    private fun saveTheme(theme: String) {
        prefs.edit().putString("thememode", theme).apply()
        themeMode = theme
        notice = "Theme saved"
    }

    /** The hidden-files preference: the path-bar toggle and the
     *  settings switch write the same state; a flip clears the
     *  selection, rows it held may have just left the view. */
    private fun saveShowHidden(on: Boolean) {
        prefs.edit().putBoolean("showhidden", on).apply()
        showHidden = on
        selection = emptySet()
    }

    /** The web's setAutoUnlock: off deletes the stored blob, on keeps
     *  a fresh one while the session is unlocked - the server flag is
     *  what the next launch reads. */
    private fun setAutoUnlock(enabled: Boolean) = saveMe(
        if (enabled) "Auto-unlock on" else "Auto-unlock off",
        { c -> c.updateMe(autoUnlock = enabled) },
        { updated ->
            if (updated.autoUnlock) {
                packedSession?.let { p ->
                    if (p.size > 40) {
                        val ark = unpackSession(p).ark
                        if (ark.isNotEmpty()) storeDeviceBlob(ark)
                    }
                }
            } else {
                prefs.edit().remove("device.${updated.id}").apply()
            }
        }
    )

    private fun changePassword(current: String, new: String) {
        val c = api ?: return
        if (busy) return
        if (new.length <8) {
            notice = "The new password needs at least8 characters"
            return
        }
        busy = true
        notice = null
        Thread {
            try {
                c.changePassword(current, new)
                runOnUiThread {
                    busy = false
                    notice = "Password changed"
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = e.message
                }
            }
        }.start()
    }

    @Composable
    private fun SettingsUi() {
        var current by remember { mutableStateOf("") }
        var fresh by remember { mutableStateOf("") }
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton({ closeSettings() }) { Text("\u2190 Back") }
                Text(
                    "Settings",
                    modifier = Modifier.weight(1f),
                    fontWeight = FontWeight.Medium
                )
                if (busy) {
                    CircularProgressIndicator(
                        Modifier.width(16.dp).height(16.dp), strokeWidth = 2.dp
                    )
                }
            }
            notice?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }
            Column(
                Modifier.weight(1f)
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 16.dp)
            ) {
                Text("Account", fontWeight = FontWeight.SemiBold)
                Text(
                    myUsername,
                    fontSize = 14.sp,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                )

                Spacer(Modifier.height(20.dp))
                Text("Display name", fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    settingsName, { settingsName = it },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Button(
                    { saveDisplayName(settingsName.trim()) },
                    enabled = !busy && settingsName.isNotBlank() &&
                        settingsName.trim() != myDisplayName,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Save display name") }

                Spacer(Modifier.height(20.dp))
                Text("Theme", fontWeight = FontWeight.SemiBold)
                Row {
                    listOf(
                        "system" to "System", "light" to "Light", "dark" to "Dark"
                    ).forEach { (value, label) ->
                        val active = themeMode == value
                        TextButton({ saveTheme(value) }, enabled = !busy) {
                            Text(
                                label,
                                color = if (active) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                                fontWeight = if (active) FontWeight.SemiBold
                                else FontWeight.Normal
                            )
                        }
                    }
                }

                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Hidden files", fontWeight = FontWeight.SemiBold)
                        Text(
                            "Show dot-entries like .env or .gitignore.",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Switch(
                        checked = showHidden,
                        onCheckedChange = { saveShowHidden(it) },
                        enabled = !busy
                    )
                }

                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Unlock automatically", fontWeight = FontWeight.SemiBold)
                        Text(
                            "Opens this account with the device key on the next " +
                                "launch - the web's switch, hardware-backed here.",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Switch(
                        checked = autoUnlock,
                        onCheckedChange = { setAutoUnlock(it) },
                        enabled = !busy
                    )
                }

                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Fingerprint unlock", fontWeight = FontWeight.SemiBold)
                        Text(
                            "Open this account with the sensor - the passphrase " +
                                "pane stays the fallback.",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    Switch(
                        checked = bioUnlock,
                        onCheckedChange = {
                            if (it) startBioEnroll() else disableBioUnlock()
                        },
                        enabled = !busy
                    )
                }

                Spacer(Modifier.height(20.dp))
                Text("Change password", fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(4.dp))
                OutlinedTextField(
                    current, { current = it },
                    label = { Text("Current password") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    fresh, { fresh = it },
                    label = { Text("New password (at least8 characters)") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Button(
                    { changePassword(current, fresh) },
                    enabled = !busy && current.isNotBlank() && fresh.isNotBlank(),
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Change password") }
                Spacer(Modifier.height(24.dp))
            }
        }
    }

    // --------------------------------------------------- text editor (S3b+)

    /** The web's markdown extensions, for the pane and the toolbar. */
    private fun isMarkdownName(name: String): Boolean =
        name.substringAfterLast('.', "").lowercase() in setOf("md", "markdown")

    /** The preview's Edit: close whatever else is up and load fresh -
     *  the editor owns its baseline, it never trusts a stale preview. */
    private fun openEditor(row: Row) {
        val c = api ?: return
        if (busy) return
        shareFor = null
        shareDialog = null
        preview = null
        rotateConfirm = false
        rowMenu = null
        deleteConfirm = null
        selection = emptySet()
        transfer = null
        trashOpen = false
        trashItems = emptyList()
        purgeConfirm = null
        emptyConfirm = false
        settingsOpen = false
        createDialog = null
        versionsOpen = false
        versionsFor = null
        versionItems = emptyList()
        deleteVersionConfirm = null
        editorCloseConfirm = false
        editorRow = row
        editorText = TextFieldValue("")
        editorBaseline = ""
        editorMd = isMarkdownName(row.name)
        // Editing first: every open starts in the source, the preview
        // pane is one tap away - never in the way of the first keystroke.
        editorMdPane = false
        editorStatus = "Loading..."
        editorStatusError = false
        editorEncrypted = row.encVersion > 0
        editorEncKey = row.encKey
        notice = null
        busy = true
        Thread {
            try {
                val raw = c.download(row.id)
                if (raw.size > 4_000_000) {
                    throw RuntimeException("Too large to edit (${raw.size / 1_000} KB)")
                }
                val content = if (row.encVersion > 0) decryptBody(c, row, raw) else raw
                val text = String(content, Charsets.UTF_8)
                runOnUiThread {
                    if (editorRow !== row) return@runOnUiThread // closed meanwhile
                    editorBaseline = text
                    editorText = TextFieldValue(text)
                    editorStatus = null
                    busy = false
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    if (editorRow === row) {
                        editorRow = null
                        editorStatus = null
                        notice = "Edit: ${e.message}"
                    }
                }
            }
        }.start()
    }

    /** PUT the editor's text through the web's save path: reuse the
     *  row's key, promote a plaintext row under a keyed folder
     *  (history=drop, exactly the web's zone write), or write plain.
     *  Every save makes the server pin the old text as a version.
     *  Returns true when the bytes are on their way to the server. */
    private fun saveEditor(closeAfter: Boolean): Boolean {
        val c = api ?: return false
        val row = editorRow ?: return false
        if (busy) return false
        val content = editorText.text
        if (content == editorBaseline) {
            if (closeAfter) closeEditorInternal()
            return true
        }
        busy = true
        editorStatus = "Saving..."
        editorStatusError = false
        Thread {
            var promoted: String? = null
            try {
                val bytes = content.toByteArray(Charsets.UTF_8)
                val rk = rootKey
                val parentKey =
                    if (rk != null) Chain.keyFor(c, rk, row.parentId) else null
                when {
                    editorEncrypted -> {
                        val wk = editorEncKey ?: row.encKey
                            ?: throw RuntimeException("This row carries no key record")
                        val pk = parentKey
                            ?: throw RuntimeException("Locked - unlock first")
                        val contentKey = FxCore.unwrapChild(pk, row.id, wk)
                        val container = FxCore.encryptBytes(row.id, contentKey, bytes)
                        // wk is the row's own enc_key - already base64,
                        // passed straight back like the web's writeText.
                        c.putContent(row.id, container, wk)
                    }
                    parentKey != null -> {
                        // The web's zone write: a plaintext row under a
                        // keyed folder turns to ciphertext here, its
                        // plaintext history going with the plaintext.
                        val fileKey = Chain.randomBytes(32)
                        val newWrapped = FxCore.wrapChild(parentKey, row.id, fileKey)
                        val container = FxCore.encryptBytes(row.id, fileKey, bytes)
                        val reply = c.putContent(
                            row.id, container,
                            java.util.Base64.getEncoder().encodeToString(newWrapped),
                            dropHistory = true
                        )
                        promoted = reply.optJSONObject("entry")?.optString("enc_key")
                            ?.takeIf { it.isNotEmpty() }
                            ?: java.util.Base64.getEncoder().encodeToString(newWrapped)
                    }
                    else -> c.putContent(row.id, bytes, null)
                }
                runOnUiThread {
                    busy = false
                    if (editorRow !== row) return@runOnUiThread
                    if (promoted != null) {
                        editorEncrypted = true
                        editorEncKey = promoted
                    }
                    editorBaseline = content
                    editorStatus = null
                    editorStatusError = false
                    loadTree() // size, modified, and the new version pin
                    if (closeAfter) closeEditorInternal()
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    if (editorRow === row) {
                        // The text stays on screen: a failed save never
                        // closes over unsaved work (the web's rule).
                        editorStatus = "Save failed: ${e.message}"
                        editorStatusError = true
                    }
                }
            }
        }.start()
        return true
    }

    /** Back or the header close: ask first when text changed. */
    private fun requestEditorClose() {
        if (editorText.text != editorBaseline) {
            editorCloseConfirm = true
        } else {
            closeEditorInternal()
        }
    }

    private fun closeEditorInternal() {
        editorRow = null
        editorText = TextFieldValue("")
        editorBaseline = ""
        editorStatus = null
        editorStatusError = false
        editorCloseConfirm = false
        editorMd = false
        editorMdPane = false
        editorEncrypted = false
        editorEncKey = null
        notice = null
    }

    /** Wrap the selection (or the cursor) with markdown markers. */
    private fun wrapEditor(before: String, after: String) {
        val v = editorText
        val text = v.text
        val start = v.selection.min.coerceIn(0, text.length)
        val end = v.selection.max.coerceIn(0, text.length)
        val newText = text.substring(0, start) + before +
            text.substring(start, end) + after + text.substring(end)
        val sel = if (start == end) {
            TextRange(start + before.length, start + before.length)
        } else {
            TextRange(start + before.length, end + before.length)
        }
        editorText = TextFieldValue(newText, selection = sel)
    }

    /** Prefix every line the selection touches (or the cursor's line). */
    private fun prefixEditorLines(prefix: String) {
        val v = editorText
        val text = v.text
        val start = v.selection.min.coerceIn(0, text.length)
        val end = v.selection.max.coerceIn(0, text.length)
        val lineStart = if (start == 0) 0 else text.lastIndexOf('\n', start - 1) + 1
        // A selection ending on a line start does not include that line.
        val regionEnd =
            if (end > start && text[end - 1] == '\n') (end - 1).coerceAtLeast(lineStart)
            else end.coerceAtLeast(lineStart)
        val region = text.substring(lineStart, regionEnd)
        val prefixed = prefix + region.replace("\n", "\n$prefix")
        val newText = text.substring(0, lineStart) + prefixed + text.substring(regionEnd)
        val lineShift = region.count { it == '\n' } + 1
        val newStart = (start + prefix.length).coerceAtMost(newText.length)
        val newEnd = if (start == end) newStart
        else (end + prefix.length * lineShift).coerceAtMost(newText.length)
        editorText = TextFieldValue(newText, selection = TextRange(newStart, newEnd))
    }

    @Composable
    private fun EditorTool(label: String, onClick: () -> Unit) {
        TextButton(onClick, enabled = !busy) {
            Text(label, fontSize = 13.sp, fontWeight = FontWeight.Medium)
        }
    }

    @Composable
    private fun EditorUi(row: Row) {
        val dirty = editorText.text != editorBaseline
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton({ requestEditorClose() }) { Text("\u2190 Back") }
                Text(
                    row.name,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium
                )
                if (editorMd) {
                    TextButton(
                        { editorMdPane = !editorMdPane },
                        enabled = !busy
                    ) { Text(if (editorMdPane) "Source" else "Preview") }
                }
                if (busy) {
                    CircularProgressIndicator(
                        Modifier.width(16.dp).height(16.dp), strokeWidth = 2.dp
                    )
                }
                TextButton(
                    { saveEditor(closeAfter = false) },
                    enabled = !busy && dirty
                ) { Text("Save") }
            }
            // Status (unsaved marker or the save error) and the web's
            // lines/chars meta, on one line to save vertical space.
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                val status = editorStatus ?: if (dirty) "* unsaved" else ""
                Text(
                    status,
                    fontSize = 13.sp,
                    color = if (editorStatusError) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onBackground.copy(alpha = 0.7f)
                    },
                    modifier = Modifier.weight(1f),
                    maxLines = 1
                )
                val body = editorText.text
                val lines = if (body.isEmpty()) 1 else body.count { it == '\n' } + 1
                Text(
                    "$lines lines \u00b7 ${body.length} chars",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.55f)
                )
            }
            if (editorMdPane) {
                // The web's pane: mdToHtml into the platform's HTML
                // renderer, links clickable (http(s) only - the port
                // rewrites everything else to "#").
                val src = editorText.text
                val html = remember(src) {
                    if (src.length > 1_000_000) null else Markdown.toHtml(src)
                }
                val color = MaterialTheme.colorScheme.onBackground
                val link = MaterialTheme.colorScheme.primary
                AndroidView(
                    factory = { ctx ->
                        TextView(ctx).apply {
                            movementMethod = LinkMovementMethod.getInstance()
                        }
                    },
                    update = { tv ->
                        tv.textSize = 14f
                        tv.setTextColor(color.toArgb())
                        tv.setLinkTextColor(link.toArgb())
                        tv.text =
                            if (html == null) src
                            else Html.fromHtml(html, Html.FROM_HTML_MODE_COMPACT)
                    },
                    modifier = Modifier.weight(1f).fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                )
            } else {
                BasicTextField(
                    value = editorText,
                    onValueChange = { editorText = it },
                    modifier = Modifier.weight(1f).fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    textStyle = TextStyle(
                        fontSize = 14.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onBackground
                    ),
                    cursorBrush = SolidColor(MaterialTheme.colorScheme.primary)
                )
            }
            if (editorMd && !editorMdPane) {
                Row(
                    Modifier.fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 4.dp, vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    EditorTool("B") { wrapEditor("**", "**") }
                    EditorTool("I") { wrapEditor("*", "*") }
                    EditorTool("H1") { prefixEditorLines("# ") }
                    EditorTool("H2") { prefixEditorLines("## ") }
                    EditorTool("\u2022") { prefixEditorLines("- ") }
                    EditorTool("1.") { prefixEditorLines("1. ") }
                    EditorTool("[]") { prefixEditorLines("- [ ] ") }
                    EditorTool(">") { prefixEditorLines("> ") }
                    EditorTool("`") { wrapEditor("`", "`") }
                    EditorTool("Link") { wrapEditor("[", "](https://)") }
                }
            }
        }
    }

    /** The editor's leave guard: save, discard, or stay. */
    @Composable
    private fun EditorCloseUi() {
        val name = editorRow?.name ?: "this file"
        AlertDialog(
            onDismissRequest = { editorCloseConfirm = false },
            title = { Text("Unsaved changes") },
            text = { Text("Save the edits to $name before closing?") },
            confirmButton = {
                TextButton(
                    {
                        editorCloseConfirm = false
                        saveEditor(closeAfter = true)
                    },
                    enabled = !busy
                ) { Text("Save") }
            },
            dismissButton = {
                Row {
                    TextButton({ editorCloseConfirm = false }) { Text("Cancel") }
                    TextButton(
                        {
                            editorCloseConfirm = false
                            closeEditorInternal()
                        }
                    ) { Text("Discard", color = MaterialTheme.colorScheme.error) }
                }
            }
        )
    }

    // ----------------------------------------------------------- versions (S5c)

    /** The row menu's Versions: close whatever else is up and load. */
    private fun openVersions(row: Row) {
        val c = api ?: return
        if (busy) return
        shareFor = null
        shareDialog = null
        preview = null
        rotateConfirm = false
        rowMenu = null
        deleteConfirm = null
        selection = emptySet()
        transfer = null
        trashOpen = false
        trashItems = emptyList()
        purgeConfirm = null
        emptyConfirm = false
        settingsOpen = false
        createDialog = null
        deleteVersionConfirm = null
        versionsFor = row
        notice = null
        versionsOpen = true
        loadVersions(c, row)
    }

    private fun loadVersions(c: ApiClient, row: Row) {
        busy = true
        Thread {
            try {
                val items = c.versions(row.id)
                runOnUiThread {
                    versionItems = items
                    busy = false
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    // A failed reload after an action keeps the view.
                    if (versionItems.isEmpty()) versionsOpen = false
                    notice = "Versions: ${e.message}"
                }
            }
        }.start()
    }

    private fun closeVersions() {
        versionsOpen = false
        versionsFor = null
        versionItems = emptyList()
        deleteVersionConfirm = null
        notice = null
        loadTree() // a restore or delete changed the file behind it
    }

    /** View one kept version through the normal preview machinery; the
     *  versions screen stays underneath (the AppUi order shows the
     *  preview first, Back returns to this list). */
    private fun previewVersion(row: Row, v: ApiClient.Version) =
        loadPreview(row, v.id, v.encVersion)

    private fun doRestoreVersion(row: Row, v: ApiClient.Version) {
        val c = api ?: return
        if (busy) return
        busy = true
        notice = null
        Thread {
            try {
                c.restoreVersion(row.id, v.id)
                runOnUiThread {
                    busy = false
                    loadVersions(c, row)
                    loadTree()
                    notice = "Version restored"
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Restore failed: ${e.message}"
                }
            }
        }.start()
    }

    private fun doDeleteVersion(row: Row, v: ApiClient.Version) {
        val c = api ?: return
        if (busy) return
        busy = true
        notice = null
        Thread {
            try {
                c.deleteVersion(row.id, v.id)
                runOnUiThread {
                    busy = false
                    loadVersions(c, row)
                    notice = "Version deleted"
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Delete version failed: ${e.message}"
                }
            }
        }.start()
    }

    @Composable
    private fun VersionsUi(row: Row) {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton({ closeVersions() }) { Text("\u2190 Back") }
                Text(
                    "Versions: ${row.name}",
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium
                )
                if (busy) {
                    CircularProgressIndicator(
                        Modifier.width(16.dp).height(16.dp), strokeWidth = 2.dp
                    )
                }
            }
            notice?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }
            if (!busy && versionItems.isEmpty()) {
                Text(
                    "No versions yet - they appear with every save of this file.",
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 24.dp)
                )
            }
            LazyColumn(Modifier.weight(1f)) {
                items(versionItems, key = { it.id }) { v ->
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                "${formatDate(v.createdAt)} \u00b7 ${formatSize(v.size)}",
                                fontSize = 14.sp
                            )
                            if (v.encVersion > 0) {
                                Text(
                                    "encrypted",
                                    fontSize = 12.sp,
                                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f)
                                )
                            }
                        }
                        TextButton(
                            { previewVersion(row, v) },
                            enabled = !busy
                        ) { Text("View") }
                        TextButton(
                            { doRestoreVersion(row, v) },
                            enabled = !busy
                        ) { Text("Restore") }
                        TextButton(
                            { deleteVersionConfirm = v },
                            enabled = !busy
                        ) { Text("Delete", color = MaterialTheme.colorScheme.error) }
                    }
                }
            }
        }
    }

    /** One kept version gone for good - the current file stays. */
    @Composable
    private fun DeleteVersionUi(row: Row, v: ApiClient.Version) {
        AlertDialog(
            onDismissRequest = { deleteVersionConfirm = null },
            title = { Text("Delete this version?") },
            text = {
                Text(
                    "The version from ${formatDate(v.createdAt)} disappears for " +
                        "good. The current file and its other versions stay."
                )
            },
            confirmButton = {
                TextButton({
                    deleteVersionConfirm = null
                    doDeleteVersion(row, v)
                }) { Text("Delete version", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton({ deleteVersionConfirm = null }) { Text("Cancel") }
            }
        )
    }

    // -------------------------------------------------------------- trash (S5a)

    /** The header's Trash: close whatever else is up and load. */
    private fun openTrash() {
        val c = api ?: return
        if (busy) return
        shareFor = null
        shareDialog = null
        preview = null
        rotateConfirm = false
        rowMenu = null
        deleteConfirm = null
        selection = emptySet()
        transfer = null
        trashOpen = true
        busy = true
        notice = null
        loadTrash(c)
    }

    private fun loadTrash(c: ApiClient) {
        busy = true
        Thread {
            try {
                val items = c.trashList().toMutableList()
                // Names at rest in the trash too (the web's single-row
                // decryptName path): what does not open keeps a marker.
                val rk = rootKey
                if (rk != null) {
                    for (i in items.indices) {
                        val t = items[i]
                        if (t.row.nameEnc != 0) {
                            items[i] = t.copy(
                                row = t.row.copy(name = Chain.decryptName(c, rk, t.row))
                            )
                        }
                    }
                }
                runOnUiThread {
                    trashItems = items
                    busy = false
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    // An initial load that fails leaves the view; a
                    // reload after an action keeps what is on screen.
                    if (trashItems.isEmpty()) trashOpen = false
                    notice = "Trash: ${e.message}"
                }
            }
        }.start()
    }

    private fun closeTrash() {
        trashOpen = false
        trashItems = emptyList()
        purgeConfirm = null
        emptyConfirm = false
        notice = null
        loadTree() // restores and purges changed what is behind
    }

    // ----------------------------------------------------------- help (web parity)

    /** The web's user dropdown, on the header's name: settings, help,
     *  sign out - the app has no admin dialog, that stays web. */
    private fun showUserMenu(anchor: View) {
        val popup = PopupMenu(this, anchor)
        popup.menu.add("Settings").setOnMenuItemClickListener {
            openSettings()
            true
        }
        popup.menu.add("Help").setOnMenuItemClickListener {
            openHelp()
            true
        }
        popup.menu.add("Sign out").setOnMenuItemClickListener {
            logout()
            true
        }
        popup.show()
    }

    /** Help -> the server's guide in-app: the same /help page the web
     *  opens, in the reader's language (the route takes ?lang=). */
    private fun openHelp() {
        if (busy) return
        shareFor = null
        shareDialog = null
        preview = null
        rotateConfirm = false
        rowMenu = null
        deleteConfirm = null
        selection = emptySet()
        transfer = null
        trashOpen = false
        trashItems = emptyList()
        purgeConfirm = null
        emptyConfirm = false
        settingsOpen = false
        closeEditorInternal()
        versionsOpen = false
        versionsFor = null
        versionItems = emptyList()
        deleteVersionConfirm = null
        val stored = prefs.getString("base", "") ?: ""
        val base = if (stored.isEmpty()) DEFAULT_SERVER
        else ApiClient.normalizeBaseUrl(stored)
        val lang = if (Locale.getDefault().language == "de") "de" else "en"
        helpUrl = "$base/help?lang=$lang"
        notice = null
        helpOpen = true
    }

    private fun closeHelp() {
        helpOpen = false
        helpUrl = ""
        helpWeb = null
        notice = null
    }

    /** The guide's own back stack first, then the overlay. */
    private fun leaveHelp() {
        val web = helpWeb
        if (web != null && web.canGoBack()) {
            web.goBack()
        } else {
            closeHelp()
        }
    }

    @Composable
    private fun HelpUi() {
        val url = helpUrl
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton({ leaveHelp() }) { Text("\u2190 Back") }
                Text(
                    "Help",
                    modifier = Modifier.weight(1f),
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium
                )
            }
            AndroidView(
                factory = { ctx ->
                    WebView(ctx).apply {
                        // The guide ships without scripts (ui.rs), so the
                        // view does not need them either - and with them
                        // off it cannot run anything the page contains.
                        settings.javaScriptEnabled = false
                        settings.domStorageEnabled = false
                        settings.allowFileAccess = false
                        settings.allowContentAccess = false
                        helpWeb = this
                        loadUrl(url)
                    }
                },
                update = { },
                onRelease = { w ->
                    if (helpWeb === w) helpWeb = null
                    w.destroy()
                },
                modifier = Modifier.weight(1f).fillMaxWidth()
            )
        }
    }

    private fun restoreTrashed(item: ApiClient.Trashed) {
        val c = api ?: return
        if (busy) return
        busy = true
        Thread {
            try {
                c.restoreTrash(item.row.id)
                runOnUiThread {
                    busy = false
                    notice = "Restored ${item.row.name}"
                    loadTrash(c)
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Restore failed: ${e.message}"
                }
            }
        }.start()
    }

    /** Called from the purge confirmation. */
    private fun purgeTrashed(item: ApiClient.Trashed) {
        val c = api ?: return
        if (busy) return
        busy = true
        Thread {
            try {
                c.purgeTrash(item.row.id)
                runOnUiThread {
                    busy = false
                    notice = "Deleted ${item.row.name} for good"
                    loadTrash(c)
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Purge failed: ${e.message}"
                }
            }
        }.start()
    }

    /** Called from the empty confirmation. */
    private fun emptyTrashNow() {
        val c = api ?: return
        if (busy) return
        busy = true
        Thread {
            try {
                c.emptyTrash()
                runOnUiThread {
                    busy = false
                    notice = "Trash emptied"
                    loadTrash(c)
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = "Empty failed: ${e.message}"
                }
            }
        }.start()
    }

    /** ISO timestamp -> "2026-11-20 09:15" (UTC as stored). */
    private fun formatDate(iso: String): String =
        if (iso.length >= 16) iso.replace('T', ' ').take(16) else iso

    @Composable
    private fun TrashUi() {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton({ closeTrash() }) { Text("\u2190 Back") }
                Text(
                    "Trash",
                    modifier = Modifier.weight(1f),
                    fontWeight = FontWeight.Medium
                )
                TextButton(
                    { emptyConfirm = true },
                    enabled = !busy && trashItems.isNotEmpty()
                ) { Text("Empty", color = MaterialTheme.colorScheme.error) }
                if (busy) {
                    CircularProgressIndicator(
                        Modifier.width(16.dp).height(16.dp), strokeWidth = 2.dp
                    )
                }
            }
            notice?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    fontSize = 13.sp,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }
            // The trash goes through the same dot-filter as the tree
            // (the web shares one renderRows for both views).
            val visibleTrash =
                if (showHidden) trashItems
                else trashItems.filter { !it.row.name.startsWith(".") }
            if (!busy && visibleTrash.isEmpty()) {
                Text(
                    if (trashItems.isNotEmpty()) {
                        "Everything here is hidden - tap Hidden to see it"
                    } else {
                        "The trash is empty"
                    },
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 24.dp)
                )
            }
            LazyColumn(Modifier.weight(1f)) {
                items(visibleTrash, key = { it.row.id }) { t ->
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(t.row.name, maxLines = 2, fontSize = 15.sp)
                            val dates = buildString {
                                if (t.deletedAt.isNotEmpty()) {
                                    append("deleted ")
                                    append(formatDate(t.deletedAt))
                                }
                                if (t.purgeAt.isNotEmpty()) {
                                    append(" \u00b7 purges ")
                                    append(formatDate(t.purgeAt))
                                }
                            }
                            Text(
                                dates,
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                            )
                        }
                        TextButton(
                            { restoreTrashed(t) },
                            enabled = !busy
                        ) { Text("Restore") }
                        TextButton(
                            { purgeConfirm = t },
                            enabled = !busy
                        ) { Text("Purge", color = MaterialTheme.colorScheme.error) }
                    }
                }
            }
        }
    }

    /** The confirmation before a purge: this one does not come back. */
    @Composable
    private fun PurgeUi(item: ApiClient.Trashed) {
        AlertDialog(
            onDismissRequest = { purgeConfirm = null },
            title = { Text("Delete for good?") },
            text = {
                Text(
                    "${item.row.name} is gone permanently - the trash is " +
                        "its last stop and a purge cannot be undone."
                )
            },
            confirmButton = {
                TextButton({
                    purgeConfirm = null
                    purgeTrashed(item)
                }) { Text("Delete forever", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton({ purgeConfirm = null }) { Text("Cancel") }
            }
        )
    }

    /** The confirmation for the whole trash. */
    @Composable
    private fun EmptyTrashUi() {
        AlertDialog(
            onDismissRequest = { emptyConfirm = false },
            title = { Text("Empty the trash?") },
            text = {
                Text(
                    "All ${trashItems.size} entries are deleted for good - " +
                        "this cannot be undone."
                )
            },
            confirmButton = {
                TextButton({
                    emptyConfirm = false
                    emptyTrashNow()
                }) { Text("Empty", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton({ emptyConfirm = false }) { Text("Cancel") }
            }
        )
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

    // ------------------------------------------- fingerprint unlock

    /** One biometric question; `onDone` runs on success only. */
    private fun askBiometric(title: String, onDone: () -> Unit) {
        val manager = BiometricManager.from(this)
        if (manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            notice = "No fingerprint enrolled on this device"
            return
        }
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    onDone()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    // A cancel is the user changing their mind, not an
                    // error worth a red line.
                    if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                    ) return
                    runOnUiThread { notice = errString.toString() }
                }
            }
        )
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
        )
    }

    /** The fingerprint twin of storeDeviceBlob: the same {v:1,
     *  deviceKeyEnc, wrappedArk} shape under `biodevice.<id>`, the
     *  device key sealed by the biometric-bound Keystore key. */
    private fun storeBioBlob(ark: ByteArray): Boolean {
        return try {
            val id = myId
            if (id == -1L) return false
            val deviceKey = Chain.randomBytes(32)
            val sealed = BioUnlock.seal(id, deviceKey) ?: return false
            val wrapped = java.util.Base64.getEncoder().encodeToString(
                FxCore.wrap(deviceKey, ark, DEVICE_AAD)
            )
            val blob = JSONObject()
                .put("v", 1)
                .put("deviceKeyEnc", sealed)
                .put("wrappedArk", wrapped)
            prefs.edit().putString("biodevice.$id", blob.toString()).apply()
            true
        } catch (e: Throwable) {
            false
        }
    }

    /** The fingerprint gate's adoption: the blob the settings switch
     *  stored, opened after a successful prompt - same shape and
     *  downstream as tryAdoptDevice (openShares included). */
    private fun tryAdoptBio(c: ApiClient, keys: String, userId: Long): ByteArray? {
        return try {
            val raw = prefs.getString("biodevice.$userId", null) ?: return null
            val blob = JSONObject(raw)
            if (blob.optInt("v", 0) != 1) return null
            val deviceKey =
                BioUnlock.open(userId, blob.getString("deviceKeyEnc")) ?: return null
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

    /** One fingerprint question -> the session, exactly like the
     *  silent device blob adopts it. A blob the sensor can no longer
     *  open (new fingerprints enrolled since) is dropped: the
     *  passphrase pane is the answer, not a retry loop. */
    private fun bioUnlockSession() {
        val c = api ?: return
        val material = keysJson ?: return
        if (busy) return
        busy = true
        notice = null
        Thread {
            val packed = tryAdoptBio(c, material, myId)
            runOnUiThread {
                if (packed == null) {
                    prefs.edit().remove("biodevice.$myId").apply()
                    bioUnlock = false
                    busy = false
                    notice = "Fingerprint unlock unavailable - unlock with your " +
                        "passphrase once and set it up again"
                } else {
                    packedSession = packed
                    rootKey = unpackSession(packed).root
                    busy = false
                    step = Step.FILES
                    loadTree()
                }
            }
        }.start()
    }

    /** Settings -> fingerprint on: one prompt, then the ARK sealed
     *  under the biometric key (auto-unlock's shape, the sensor as
     *  the gate). */
    private fun startBioEnroll() {
        val packed = packedSession
        if (packed == null || packed.size <= 40) {
            notice = "Unlock once with your passphrase first"
            return
        }
        askBiometric("Enable fingerprint unlock") {
            Thread {
                val ark = unpackSession(packed).ark
                val ok = ark.isNotEmpty() && storeBioBlob(ark)
                runOnUiThread {
                    if (ok) {
                        bioUnlock = true
                        notice = "Fingerprint unlock on"
                    } else {
                        notice = "Could not store the fingerprint secret"
                    }
                }
            }.start()
        }
    }

    private fun disableBioUnlock() {
        prefs.edit().remove("biodevice.$myId").apply()
        bioUnlock = false
        notice = "Fingerprint unlock off"
    }

    /** The pane's gate: a stored blob and a sensor that
     *  authenticates right now. */
    private fun bioAvailable(): Boolean {
        if (myId == -1L) return false
        if (prefs.getString("biodevice.$myId", null) == null) return false
        return BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
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
        // The header's shape follows the step (see the wiring above).
        LaunchedEffect(step) {
            // The user menu carries the way out (and help, and the
            // settings) wherever a session exists to act on - the
            // web's dropdown, in the header that has always rendered.
            findViewById<TextView>(R.id.headerUser).visibility =
                if (step == Step.LOGIN) View.GONE else View.VISIBLE
            findViewById<TextView>(R.id.headerUser).text =
                (if (myUsername.isEmpty()) "Account" else myUsername) + " \u25BE"
            // Trash is a destination of the file screens only.
            findViewById<ImageView>(R.id.headerTrash).visibility =
                if (step == Step.FILES) View.VISIBLE else View.GONE
        }
        // The server's theme over the system default (the web's
        // theme section): "system" defers to the device.
        val dark = when (themeMode) {
            "dark" -> true
            "light" -> false
            else -> isSystemInDarkTheme()
        }
        MaterialTheme(
            // The feature graphic's field becomes the light theme's
            // canvas (device pass: "use this subtle light blue as the
            // background everywhere"); primary darkens to the shadow
            // blue so links and buttons stay readable on it. The dark
            // scheme stays untouched - the blue on dark would not.
            colorScheme = if (dark) darkColorScheme() else lightColorScheme().copy(
                background = Color(0xFFD5EEFB),
                primary = Color(0xFF00598F)
            )
        ) {
            // MaterialTheme only provides colors; Surface paints them.
            // Without this the screens are transparent and the dark XML
            // window shows through under light-mode text - unreadable.
            Surface(Modifier.fillMaxSize()) {
                val sharing = shareFor
                val shown = preview
                val vrow = versionsFor
                val erow = editorRow
                when {
                    trashOpen -> TrashUi()
                    helpOpen -> HelpUi()
                    settingsOpen -> SettingsUi()
                    sharing != null -> ShareUi(sharing)
                    shown != null -> PreviewUi(shown)
                    // The editor took the preview's place; a version's
                    // preview (no Edit there) still sits above its list.
                    erow != null -> EditorUi(erow)
                    versionsOpen && vrow != null -> VersionsUi(vrow)
                    step == Step.LOGIN -> LoginUi()
                    step == Step.PASSPHRASE -> UnlockUi()
                    else -> FilesUi()
                }
                // Row-action dialogs: they float above whichever screen
                // is up (AlertDialogs live in their own window).
                createDialog?.let { CreateUi(it) }
                rowMenu?.let { RowMenuUi(it) }
                deleteConfirm?.let { DeleteUi(it) }
                purgeConfirm?.let { PurgeUi(it) }
                if (emptyConfirm) EmptyTrashUi()
                deleteVersionConfirm?.let { v ->
                    vrow?.let { r -> DeleteVersionUi(r, v) }
                }
                if (editorCloseConfirm) EditorCloseUi()
            }
        }
    }

    @Composable
    private fun LoginUi() {
        val storedServer = prefs.getString("base", "") ?: ""
        var server by remember {
            mutableStateOf(if (storedServer.isEmpty()) DEFAULT_SERVER else storedServer)
        }
        var user by remember { mutableStateOf(prefs.getString("user", "") ?: "") }
        var password by remember { mutableStateOf("") }
        var displayName by remember { mutableStateOf("") }
        var registerMode by remember { mutableStateOf(false) }
        var serverBanner by remember { mutableStateOf("") }
        // The deployment's notice, re-read when the server field
        // settles: a banner belongs to the server it names.
        LaunchedEffect(server) {
            delay(600)
            val target = server
            Thread {
                val text = try {
                    ApiClient(target).loginBanner()
                } catch (e: Throwable) {
                    ""
                }
                runOnUiThread { if (server == target) serverBanner = text }
            }.start()
        }
        Column(
            // Scrollable: register mode plus a keyboard leaves no
            // screen that fits without it - everything must stay
            // reachable, especially the feedback line.
            Modifier.fillMaxSize()
                .padding(horizontal = 24.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            if (serverBanner.isNotEmpty()) {
                val warn =
                    if (isSystemInDarkTheme()) Color(0xFFFFC164) else Color(0xFF7A4A00)
                Text(
                    serverBanner,
                    fontSize = 13.sp,
                    lineHeight = 18.sp,
                    color = warn,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color(0x24F59E0B), RoundedCornerShape(8.dp))
                        .padding(horizontal = 12.dp, vertical = 10.dp)
                )
                Spacer(Modifier.height(12.dp))
            }
            // The feedback belongs where the eye is: above the form,
            // not below the fold - on small screens (or with the
            // keyboard up) a bottom notice never gets seen, which is
            // exactly how "the account was created, but nobody said
            // so" happens.
            notice?.let {
                Text(
                    it,
                    color = MaterialTheme.colorScheme.error,
                    fontSize = 14.sp,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
            }
            // The feature graphic's mark as the hero of the form: the
            // same cloud the store banner shows, on the light blue field.
            Image(
                painter = painterResource(R.drawable.ic_launcher_foreground),
                contentDescription = "fxcloud",
                modifier = Modifier.size(140.dp)
            )
            Spacer(Modifier.height(20.dp))
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
                label = {
                    Text(if (registerMode) "Password (min8 characters)" else "Password")
                },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
            if (registerMode) {
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    displayName, { displayName = it },
                    label = { Text("Display name (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    "A username needs3+ characters, a password8+.",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                )
            }
            Spacer(Modifier.height(16.dp))
            Button(
                {
                    if (registerMode) {
                        doRegister(server, user, password, displayName)
                    } else {
                        doLogin(server, user, password)
                    }
                },
                enabled = !busy && server.isNotBlank() && user.isNotBlank() &&
                    password.isNotBlank() &&
                    (!registerMode || (password.length >= 8 && user.length >= 3)),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (busy) {
                    CircularProgressIndicator(Modifier.height(18.dp).width(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(if (registerMode) "Create account" else "Sign in")
                }
            }
            TextButton({
                registerMode = !registerMode
                password = ""
                notice = null
            }) {
                Text(
                    if (registerMode) "Have an account? Sign in"
                    else "No account yet? Create one"
                )
            }
        }
    }

    @Composable
    private fun UnlockUi() {
        var secret by remember { mutableStateOf("") }
        var recovery by remember { mutableStateOf(false) }
        // The fingerprint gate asks on its own when the pane appears;
        // the button below repeats the question after a cancel.
        LaunchedEffect(Unit) {
            if (bioAvailable()) {
                askBiometric("Unlock fxcloud") { bioUnlockSession() }
            }
        }
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
            if (bioAvailable()) {
                TextButton(
                    { askBiometric("Unlock fxcloud") { bioUnlockSession() } },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Unlock with fingerprint") }
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
                if (selection.isNotEmpty()) {
                    TextButton({ selection = emptySet() }) { Text("\u2715") }
                }
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
                // The web's hidden-toggle in the toolbar: dot-entries
                // are off by default, this flips them for the listing
                // (and the gallery swipe) without a refetch.
                TextButton({ saveShowHidden(!showHidden) }, enabled = !busy) {
                    Text(
                        "Hidden",
                        fontSize = 13.sp,
                        color = if (showHidden) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.45f),
                        fontWeight = if (showHidden) FontWeight.SemiBold
                        else FontWeight.Normal
                    )
                }
                when {
                    transfer != null -> {
                        TextButton({ cancelTransfer() }) { Text("Cancel") }
                        TextButton({ executeTransfer() }, enabled = !busy) {
                            Text(if (transfer!!.copy) "Copy here" else "Move here")
                        }
                    }
                    selection.isNotEmpty() -> SelectionActions()
                    else -> CreateMenu()
                }
                if (busy) {
                    CircularProgressIndicator(Modifier.width(16.dp).height(16.dp), strokeWidth = 2.dp)
                }
                // The way out sits in the XML header's user menu - the
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
                // The web's renderRows rule: dot-entries only with the
                // toggle on - and a folder whose entries are all hidden
                // says so instead of claiming it is empty.
                val visible =
                    if (showHidden) rows
                    else rows.filter { !it.name.startsWith(".") }
                if (visible.isEmpty() && !busy) {
                    item {
                        Text(
                            if (rows.isNotEmpty()) {
                                "Everything here is hidden - tap Hidden in the path bar"
                            } else {
                                "This folder is empty"
                            },
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 24.dp)
                        )
                    }
                }
                items(visible, key = { it.id }) { row ->
                    val selected = row.id in selection
                    val tint =
                        if (selected) {
                            Modifier.background(
                                MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)
                            )
                        } else {
                            Modifier
                        }
                    Row(
                        Modifier.fillMaxWidth()
                            .then(tint)
                            .combinedClickable(
                                onClick = {
                                    if (selection.isNotEmpty()) toggleSelect(row.id)
                                    else onRow(row)
                                },
                                onLongClick = {
                                    // Long press selects: the first press
                                    // starts the selection with this row,
                                    // another one adds or drops it. While
                                    // picking a destination: nothing.
                                    if (transfer == null) toggleSelect(row.id)
                                }
                            )
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        if (selection.isNotEmpty()) {
                            Checkbox(
                                checked = selected,
                                onCheckedChange = { toggleSelect(row.id) }
                            )
                        }
                        Text(if (row.isDir) "\uD83D\uDCC1" else "\uD83D\uDCC4")
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(row.name, maxLines = 2)
                            if (!row.isDir) {
                                Text(
                                    formatSize(row.size),
                                    fontSize = 12.sp,
                                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                                )
                            }
                        }
                        if (selection.isEmpty() && transfer == null) {
                            TextButton({ rowMenu = row }) { Text("\u22EE", fontSize = 18.sp) }
                        }
                    }
                }
            }
        }
    }

    /** S4a: share one row or a selection - grantee picker, fingerprint
     *  with TOFU, permissions, the existing shares (one row only), and
     *  the confirm dialogs before anything is sealed. */
    @Composable
    private fun ShareUi(rows: List<Row>) {
        var menuOpen by remember { mutableStateOf(false) }
        val single = rows.singleOrNull()
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
                    if (single != null) "Share: ${single.name}"
                    else "Share ${rows.size} items",
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
                if (single != null) {
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
                }
                notice?.let {
                    Spacer(Modifier.height(8.dp))
                    Text(it, color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
                }
                Spacer(Modifier.height(16.dp))
            }
        }
        shareDialog?.let { ShareDialogUi(it, rows) }
    }

    /** The two TOFU states and the web's no-key warning (app.js). */
    @Composable
    private fun ShareDialogUi(d: ShareDialog, rows: List<Row>) {
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
                        doSealShare(rows, d.user, d.pub, d.mask)
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
                        doSealShare(rows, d.user, d.pub, d.mask)
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
                        doSealShare(rows, d.user, null, d.mask)
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
                if (p.kind == Kind.TEXT && p.allowRotate) {
                    TextButton({ openEditor(p.row) }, enabled = !busy) {
                        Text("Edit")
                    }
                }
                if (p.allowRotate && p.row.encVersion > 0 && !p.row.isDir && p.row.ownerId == myId) {
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
                    Modifier.fillMaxSize().padding(8.dp)
                        // The gallery gesture: sideways steps through the
                        // folder's previewables (the web's arrows as a
                        // gesture), down closes - next to the ← button
                        // and the system back, the exit a swiped view
                        // needs. Axis is locked after the touch slop so
                        // a diagonal flick picks one direction only.
                        .pointerInput(p.row.id) {
                            val minSwipe = 48.dp.toPx()
                            var accX = 0f
                            var accY = 0f
                            var axis = 0 // 0 undecided, 1 across, 2 down
                            detectDragGestures(
                                onDragStart = {
                                    accX = 0f
                                    accY = 0f
                                    axis = 0
                                },
                                onDrag = { change, drag ->
                                    change.consume()
                                    accX += drag.x
                                    accY += drag.y
                                    if (axis == 0 &&
                                        (abs(accX) > viewConfiguration.touchSlop ||
                                            abs(accY) > viewConfiguration.touchSlop)
                                    ) {
                                        axis = if (abs(accX) > abs(accY)) 1 else 2
                                    }
                                },
                                onDragEnd = {
                                    when {
                                        axis == 1 && accX <= -minSwipe -> swipePreview(1)
                                        axis == 1 && accX >= minSwipe -> swipePreview(-1)
                                        axis == 2 && accY >= minSwipe -> {
                                            preview = null
                                            rotateConfirm = false
                                        }
                                    }
                                }
                            )
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Image(
                        bitmap = p.bitmap!!.asImageBitmap(),
                        contentDescription = p.row.name,
                        modifier = Modifier.fillMaxSize(),
                        contentScale = ContentScale.Fit
                    )
                }
                Kind.PDF -> {
                    val pages = p.pages ?: emptyList()
                    var page by remember(p) { mutableStateOf(0) }
                    Column(Modifier.fillMaxSize()) {
                        Box(
                            Modifier.weight(1f).padding(8.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            if (pages.isNotEmpty()) {
                                Image(
                                    bitmap = pages[page.coerceIn(0, pages.lastIndex)]
                                        .asImageBitmap(),
                                    contentDescription =
                                        "${p.row.name}, page ${page + 1} von ${pages.size}",
                                    modifier = Modifier.fillMaxSize(),
                                    contentScale = ContentScale.Fit
                                )
                            }
                        }
                        Row(
                            Modifier.fillMaxWidth()
                                .padding(horizontal = 8.dp, vertical = 4.dp),
                            horizontalArrangement = Arrangement.Center,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            TextButton(
                                { page = (page - 1).coerceAtLeast(0) },
                                enabled = page > 0
                            ) { Text("\u2190") }
                            val label =
                                if (p.pdfTotal > pages.size) "${page + 1} / ${p.pdfTotal}+ (first ${pages.size})"
                                else "${page + 1} / ${pages.size}"
                            Text(
                                label,
                                fontSize = 14.sp,
                                modifier = Modifier.padding(horizontal = 12.dp)
                            )
                            TextButton(
                                { page = (page + 1).coerceAtMost(pages.lastIndex) },
                                enabled = page < pages.lastIndex
                            ) { Text("\u2192") }
                        }
                    }
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
