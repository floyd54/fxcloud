package de.frischux.fxcloud

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.os.Bundle
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
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

/** A rendered preview (S3b): decoded bitmap or text, held in memory. */
private class Preview(
    val name: String,
    val kind: Kind,
    val bitmap: Bitmap? = null,
    val text: String? = null
)

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
                val id = c.me() // throws when the session is gone
                val keys = c.keysOrNull()
                runOnUiThread {
                    api = c
                    myId = id
                    keysJson = keys
                    busy = false
                    if (keys != null) {
                        // Memory-only material: unlock again, exactly like
                        // the browser does after a reload.
                        step = Step.PASSPHRASE
                    } else {
                        step = Step.FILES
                        loadTree()
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
                val id = c.me()
                val keys = c.keysOrNull()
                runOnUiThread {
                    api = c
                    myId = id
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
                        else -> unlockWith(password) { step = Step.PASSPHRASE }
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

    private fun doUnlock(password: String) = unlockWith(password) { msg ->
        notice = msg ?: "Unlock failed"
    }

    /**
     * Argon2id and the ARK chain run in Rust (S2a); a wrong secret
     * throws with the unified unwrap message. `onFail` decides where a
     * failure lands - the passphrase screen after a fresh sign-in (the
     * web's handoff failing is "the pane is the fallback, not an
     * error"), the same screen with a message when typed there.
     */
    private fun unlockWith(password: String, onFail: (String?) -> Unit) {
        val material = keysJson ?: return
        busy = true
        notice = null
        Thread {
            try {
                val packed = FxCore.unlock(material, password)
                runOnUiThread {
                    packedSession = packed
                    rootKey = packed.copyOfRange(0, 32)
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
            // A preview closes before the tree walks: back means "out of
            // the file", then "up a directory", then "out of the app".
            preview != null -> preview = null
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
                        Preview(row.name, kind, bitmap = bitmap)
                    }
                    else -> {
                        if (content.size > 4_000_000) {
                            throw RuntimeException(
                                "Text too large to display (${content.size / 1_000} KB)"
                            )
                        }
                        Preview(row.name, kind, text = String(content, Charsets.UTF_8))
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
                val shown = preview
                if (shown != null) {
                    PreviewUi(shown)
                } else {
                    when (step) {
                        Step.LOGIN -> LoginUi()
                        Step.PASSPHRASE -> UnlockUi()
                        Step.FILES -> FilesUi()
                    }
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
        var password by remember { mutableStateOf("") }
        Column(
            Modifier.fillMaxSize().padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.Center
        ) {
            Text("This account is encrypted.")
            Spacer(Modifier.height(4.dp))
            Text(
                "Enter your storage passphrase to unlock it for this session.",
                fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
            )
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(
                password, { password = it },
                label = { Text("Storage passphrase") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(16.dp))
            Button(
                { doUnlock(password) },
                enabled = !busy && password.isNotBlank(),
                modifier = Modifier.fillMaxWidth()
            ) {
                if (busy) {
                    CircularProgressIndicator(Modifier.height(18.dp).width(18.dp), strokeWidth = 2.dp)
                } else {
                    Text("Unlock")
                }
            }
            notice?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, color = MaterialTheme.colorScheme.error)
            }
        }
    }

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
                    val path = crumbs.ifEmpty { listOf(Crumb(null, "Home", 0)) }
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
                            .clickable { onRow(row) }
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

    /** The S3b preview: a top bar with back and name, then the content. */
    @Composable
    private fun PreviewUi(p: Preview) {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton({ preview = null }) { Text("\u2190 Back") }
                Text(
                    p.name,
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
            when (p.kind) {
                Kind.IMAGE -> Box(
                    Modifier.fillMaxSize().padding(8.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Image(
                        bitmap = p.bitmap!!.asImageBitmap(),
                        contentDescription = p.name,
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
    }

    private fun formatSize(bytes: Long): String = when {
        bytes >= 1_073_741_824L -> "%.1f GB".format(bytes / 1_073_741_824.0)
        bytes >= 1_048_576L -> "%.1f MB".format(bytes / 1_048_576.0)
        bytes >= 1_024L -> "%.1f KB".format(bytes / 1_024.0)
        else -> "$bytes B"
    }
}
