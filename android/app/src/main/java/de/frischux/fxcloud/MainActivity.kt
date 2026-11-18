package de.frischux.fxcloud

import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONArray
import org.json.JSONObject

/** The three stops of S2: sign in, unlock (encrypted accounts), browse. */
private enum class Step { LOGIN, PASSPHRASE, FILES }

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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            setContentView(R.layout.activity_main)
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
                    .putString("base", server.trimEnd('/'))
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
                    if (keys != null) {
                        step = Step.PASSPHRASE
                    } else {
                        step = Step.FILES
                        loadTree()
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

    private fun doUnlock(password: String) {
        val material = keysJson ?: return
        busy = true
        notice = null
        Thread {
            try {
                // Argon2id and the ARK chain run in Rust (S2a); throws on a
                // wrong passphrase with the unified unwrap message.
                val packed = FxCore.unlock(material, password)
                val root = packed.copyOfRange(0, 32)
                runOnUiThread {
                    packedSession = packed
                    rootKey = root
                    busy = false
                    step = Step.FILES
                    loadTree()
                }
            } catch (e: Throwable) {
                runOnUiThread {
                    busy = false
                    notice = e.message ?: "Unlock failed"
                }
            }
        }.start()
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
        parent = id
        loadTree()
    }

    private fun onRow(row: Row) {
        if (row.isDir) {
            openFolder(row.id)
        } else {
            // S3: download, preview, upload (concepts/android.md).
            notice = "Opening files arrives with S3 (download and preview)"
        }
    }

    // ------------------------------------------------------------------- ui

    @Composable
    private fun AppUi() {
        MaterialTheme(
            colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()
        ) {
            when (step) {
                Step.LOGIN -> LoginUi()
                Step.PASSPHRASE -> UnlockUi()
                Step.FILES -> FilesUi()
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
                Modifier.fillMaxWidth().padding(horizontal = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    Modifier.weight(1f).horizontalScroll(rememberScrollState()),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    crumbs.forEachIndexed { i, crumb ->
                        TextButton({
                            if (crumb.id != parent) openFolder(crumb.id)
                        }) {
                            Text(if (i == 0) "\u2302" else crumb.name, maxLines = 1)
                        }
                        if (i < crumbs.lastIndex) Text("/")
                    }
                }
                if (busy) {
                    CircularProgressIndicator(Modifier.width(16.dp).height(16.dp), strokeWidth = 2.dp)
                }
                TextButton({ logout() }) { Text("Logout") }
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

    private fun formatSize(bytes: Long): String = when {
        bytes >= 1_073_741_824L -> "%.1f GB".format(bytes / 1_073_741_824.0)
        bytes >= 1_048_576L -> "%.1f MB".format(bytes / 1_048_576.0)
        bytes >= 1_024L -> "%.1f KB".format(bytes / 1_024.0)
        else -> "$bytes B"
    }
}
