(function () {
  "use strict";

  const rowsEl = document.getElementById("file-rows");
  const breadcrumbEl = document.getElementById("breadcrumb");
  const fileInput = document.getElementById("file-input");
  const folderInput = document.getElementById("folder-input");
  const dropzone = document.getElementById("dropzone");

  // Current folder id (null == root).
  let currentParent = null;
  // Viewer's permission mask in the current folder (root is always full).
  let currentPerms = 31;
  // Known permission masks per folder id (learned from listings/info calls).
  const folderPerms = {};
  // The signed-in user's id (to tell own items from shared ones).
  let meId = null;

  // Multi-selection: id -> entry, as shown in the current listing.
  const selected = new Map();
  // The current listing (for "select all" and shift-click ranges) and the
  // position of the last checkbox the user toggled.
  let currentEntries = [];
  let lastCheckIndex = null;

  // Nextcloud-style permission bits.
  const PERM_READ = 1, PERM_UPDATE = 2, PERM_CREATE = 4, PERM_DELETE = 8,
        PERM_SHARE = 16, PERM_ALL = 31;

  // ---------- helpers ----------
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function formatSize(bytes) {
    if (bytes === 0) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    const value = bytes / Math.pow(1024, i);
    return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  function formatDate(iso) {
    const d = new Date(iso);
    if (isNaN(d)) return "";
    return d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  }

  function iconFor(entry) {
    return entry.is_dir
      ? '<span class="icon folder">📁</span>'
      : '<span class="icon">📄</span>';
  }

  async function api(url, options) {
    const res = await fetch(url, options);
    if (res.status === 401) {
      window.location.href = "/login";
      throw new Error("unauthorized");
    }
    if (!res.ok) {
      let message = `Request failed (${res.status})`;
      try {
        const body = await res.json();
        if (body.error) message = body.error;
      } catch (_) {}
      throw new Error(message);
    }
    return res;
  }

  // ---------- rendering ----------
  function renderBreadcrumb(crumbs) {
    breadcrumbEl.innerHTML = "";
    crumbs.forEach((crumb, idx) => {
      const isLast = idx === crumbs.length - 1;
      if (idx > 0) {
        const sep = document.createElement("span");
        sep.className = "sep";
        sep.textContent = "›";
        breadcrumbEl.appendChild(sep);
      }
      if (isLast) {
        const cur = document.createElement("span");
        cur.className = "current";
        cur.textContent = crumb.name;
        breadcrumbEl.appendChild(cur);
      } else {
        const a = document.createElement("a");
        a.textContent = crumb.name;
        a.addEventListener("click", () => openFolder(crumb.id));
        breadcrumbEl.appendChild(a);
      }
    });
  }

  function renderRows(entries) {
    rowsEl.innerHTML = "";
    currentEntries = entries;
    if (entries.length === 0) {
      rowsEl.innerHTML =
        '<tr><td colspan="5"><div class="empty"><div class="big">📂</div>' +
        "This folder is empty.<br/>Upload a file or create a folder to get started.</div></td></tr>";
      return;
    }

    entries.forEach((entry, index) => {
      const tr = document.createElement("tr");
      tr.dataset.id = String(entry.id);
      if (selected.has(entry.id)) tr.classList.add("selected");

      // Selection checkbox; Shift+click extends over a range of rows.
      const checkTd = document.createElement("td");
      checkTd.className = "check-col";
      const box = document.createElement("input");
      box.type = "checkbox";
      box.checked = selected.has(entry.id);
      box.title = "Select";
      box.addEventListener("click", (e) => {
        e.stopPropagation();
        toggleRowSelection(entry, index, box.checked, e.shiftKey);
      });
      checkTd.appendChild(box);

      const nameTd = document.createElement("td");
      nameTd.innerHTML =
        '<div class="name-cell">' + iconFor(entry) +
        '<div><div>' + escapeHtml(entry.name) +
        (entry.owner_name
          ? ' <span class="shared-badge">↔ ' + escapeHtml(entry.owner_name) + "</span>"
          : "") +
        '<div class="meta-mobile">' +
        (entry.is_dir ? "Folder" : formatSize(entry.size)) + " · " +
        formatDate(entry.modified_at) + "</div></div></div></div>";

      const sizeTd = document.createElement("td");
      sizeTd.className = "size-col";
      if (entry.is_dir) {
        sizeTd.textContent =
          entry.subtree_bytes != null ? formatSize(entry.subtree_bytes) : "—";
      } else {
        sizeTd.textContent = formatSize(entry.size);
      }

      const dateTd = document.createElement("td");
      dateTd.className = "date-col";
      dateTd.textContent = formatDate(entry.modified_at);

      const actionsTd = document.createElement("td");
      actionsTd.className = "actions-col";

      const perms = permsOf(entry);
      const isOwner = entry.owner_id === meId;

      // Single "⋮" button; all actions live in a popup menu.
      const kebab = document.createElement("button");
      kebab.type = "button";
      kebab.className = "kebab";
      kebab.title = "Actions";
      kebab.textContent = "⋮";
      kebab.addEventListener("click", (e) => {
        e.stopPropagation();
        toggleRowMenu(kebab, entry, perms, isOwner);
      });
      actionsTd.appendChild(kebab);

      tr.appendChild(checkTd);
      tr.appendChild(nameTd);
      tr.appendChild(sizeTd);
      tr.appendChild(dateTd);
      tr.appendChild(actionsTd);

      if (entry.is_dir) {
        tr.addEventListener("click", () => openFolder(entry.id, perms));
      } else if ((perms & PERM_READ) && previewKind(entry.name)) {
        // Browser-viewable files open in the lightbox directly.
        tr.classList.add("previewable");
        tr.addEventListener("click", () => openPreview(entry));
      }

      rowsEl.appendChild(tr);
    });
  }

  // ---------- selection (multi-select) ----------
  function permsOf(entry) {
    return entry.permissions == null ? PERM_ALL : entry.permissions;
  }

  function setSelected(entry, on) {
    if (on) selected.set(entry.id, entry);
    else selected.delete(entry.id);
  }

  function toggleRowSelection(entry, index, checked, shift) {
    if (shift && lastCheckIndex != null) {
      // Shift+click: apply the new state to everything between the two rows.
      const from = Math.min(lastCheckIndex, index);
      const to = Math.max(lastCheckIndex, index);
      for (let i = from; i <= to; i++) setSelected(currentEntries[i], checked);
    } else {
      setSelected(entry, checked);
    }
    lastCheckIndex = index;
    syncSelectionUi();
  }

  function clearSelection() {
    selected.clear();
    lastCheckIndex = null;
    syncSelectionUi();
  }

  // Selected items an action is allowed to touch (per-entry permission bits).
  function eligible(pred) {
    return [...selected.values()].filter(pred);
  }

  function syncSelectionUi() {
    for (const tr of rowsEl.querySelectorAll("tr[data-id]")) {
      const on = selected.has(Number(tr.dataset.id));
      tr.classList.toggle("selected", on);
      const box = tr.querySelector(".check-col input");
      if (box) box.checked = on;
    }

    // Header checkbox: checked when all rows are in, indeterminate when some.
    const all = document.getElementById("select-all");
    const count = currentEntries.filter((e) => selected.has(e.id)).length;
    all.checked = currentEntries.length > 0 && count === currentEntries.length;
    all.indeterminate = count > 0 && count < currentEntries.length;

    updateBulkBar();
  }

  function updateBulkBar() {
    const bar = document.getElementById("bulkbar");
    bar.style.display = selected.size === 0 ? "none" : "";
    if (selected.size === 0) return;

    document.getElementById("bulk-count").textContent =
      selected.size === 1 ? "1 item selected" : `${selected.size} items selected`;

    const enable = (id, can) => {
      document.getElementById(id).disabled = !can;
    };
    enable("bulk-download", eligible((e) => permsOf(e) & PERM_READ).length > 0);
    enable("bulk-move", eligible((e) => permsOf(e) & PERM_UPDATE).length > 0);
    enable("bulk-copy", eligible((e) => permsOf(e) & PERM_READ).length > 0);
    enable("bulk-share", eligible((e) => e.owner_id === meId).length > 0);
    enable("bulk-delete", eligible((e) => permsOf(e) & PERM_DELETE).length > 0);
  }

  // Show which items a batch skipped because the caller lacks the permission.
  function skippedNote(done) {
    const missing = selected.size - done;
    return missing > 0
      ? `\n\n${missing} of ${selected.size} selected item(s) skipped — missing permission.`
      : "";
  }

  // Turn one batch response into user feedback (partial failures are normal).
  function reportOutcome(out) {
    if (!out || !out.failed || out.failed.length === 0) return;
    const lines = out.failed
      .slice(0, 8)
      .map((f) => `${f.name || "#" + f.id}: ${f.error}`);
    alert(
      `${out.failed.length} of ${out.failed.length + out.ok.length} item(s) failed:\n\n` +
        lines.join("\n") +
        (out.failed.length > 8 ? "\n…" : "")
    );
  }

  // ---------- row action menu ----------
  let openMenu = null; // currently shown popup (with an ._owner button)

  function closeRowMenu() {
    if (openMenu) {
      openMenu.remove();
      openMenu = null;
    }
  }

  function toggleRowMenu(btn, entry, perms, isOwner) {
    if (openMenu && openMenu._owner === btn) {
      closeRowMenu();
      return;
    }
    closeRowMenu();

    const menu = document.createElement("div");
    menu.className = "row-menu";
    menu._owner = btn;

    // Context-sensitive items, gated by the viewer's permission mask.
    // Re-sharing (PERM_SHARE bit) needs cascading shares on the backend;
    // for now only the owner manages an item's shares.
    const items = [];
    if (entry.is_dir) {
      items.push(["Open", () => openFolder(entry.id, perms)]);
    }
    if (!entry.is_dir && (perms & PERM_READ)) {
      if (previewKind(entry.name)) {
        // Text files open in the editor; everything else gets a preview.
        const label = previewKind(entry.name) === "text" ? "Edit" : "Preview";
        items.push([label, () => openPreview(entry)]);
      }
      items.push(["Download", () => downloadFile(entry.id, entry.name)]);
    }
    if (isOwner) {
      items.push(["Share", () => openShareDialog([entry])]);
    }
    if (perms & PERM_UPDATE) {
      items.push(["Move to…", () => openTransferDialog("move", [entry])]);
    }
    if (perms & PERM_READ) {
      items.push(["Copy to…", () => openTransferDialog("copy", [entry])]);
    }
    if (perms & PERM_UPDATE) {
      items.push(["Rename", () => renameEntry(entry.id, entry.name)]);
    }
    if (perms & PERM_DELETE) {
      items.push(["Delete", () => deleteEntry(entry.id, entry.is_dir, entry.name), true]);
    }

    for (const [label, fn, danger] of items) {
      const it = document.createElement("button");
      it.type = "button";
      it.className = "row-menu-item" + (danger ? " danger" : "");
      it.textContent = label;
      it.addEventListener("click", (e) => {
        e.stopPropagation();
        closeRowMenu();
        fn();
      });
      menu.appendChild(it);
    }

    document.body.appendChild(menu);
    // Anchor to the kebab, kept inside the viewport.
    const r = btn.getBoundingClientRect();
    menu.style.top = Math.min(r.bottom + 4, window.innerHeight - menu.offsetHeight - 8) + "px";
    const left = Math.min(r.right - menu.offsetWidth, window.innerWidth - menu.offsetWidth - 8);
    menu.style.left = Math.max(8, left) + "px";
    openMenu = menu;
  }

  // Close the popup on outside clicks, Escape, and layout changes.
  document.addEventListener("click", closeRowMenu);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeRowMenu();
      closePreview();
    }
  });
  window.addEventListener("resize", closeRowMenu);
  window.addEventListener("scroll", closeRowMenu, true);

  // ---------- data loading ----------
  async function loadFiles(parent) {
    const url = parent == null ? "/api/files" : `/api/files?parent=${parent}`;
    const [listRes, crumbRes] = await Promise.all([
      api(url).then((r) => r.json()),
      parent == null
        ? Promise.resolve({ breadcrumbs: [{ id: null, name: "Home" }] })
        : api(`/api/files/breadcrumb?id=${parent}`).then((r) => r.json()),
    ]);
    renderBreadcrumb(crumbRes.breadcrumbs);
    // Navigating starts a fresh selection — the old one described another folder.
    selected.clear();
    lastCheckIndex = null;
    renderRows(listRes.entries);
    currentPerms =
      parent == null || folderPerms[parent] == null ? PERM_ALL : folderPerms[parent];
    renderToolbar();
    syncSelectionUi();
    // Every mutation (upload, delete, copy, rename, …) ends with a list
    // reload, so refreshing the quota readout here keeps it always current.
    loadMe().catch(() => {});
  }

  // Show the create toolbar only where the viewer holds CREATE.
  function renderToolbar() {
    const canCreate = (currentPerms & PERM_CREATE) !== 0;
    const show = canCreate ? "" : "none";
    document.getElementById("new-file-btn").style.display = show;
    document.getElementById("new-folder-btn").style.display = show;
    document.getElementById("upload-btn").style.display = show;
    document.getElementById("upload-folder-btn").style.display = show;
    dropzone.style.display = show;
  }

  // Binary units (1024-based), matching the server's quota messages, so the
  // topbar and a 507 error always describe the same numbers.
  function fmtBytes(n) {
    if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " GB";
    if (n >= 1048576) return Math.round(n / 1048576) + " MB";
    if (n >= 1024) return Math.round(n / 1024) + " KB";
    return n + " B";
  }

  async function loadMe() {
    const res = await api("/api/me").then((r) => r.json());
    meId = res.id;
    document.getElementById("user-label").textContent =
      res.display_name || res.username;
    const storage = document.getElementById("storage-label");
    if (storage && res.used_bytes != null && res.quota_bytes != null) {
      storage.textContent = `${fmtBytes(res.used_bytes)} of ${fmtBytes(res.quota_bytes)}`;
      storage.title = "storage used of quota";
    }
  }

  // ---------- actions ----------
  async function openFolder(id, perms) {
    currentParent = id;
    if (id != null) {
      if (perms != null) {
        folderPerms[id] = perms;
      } else if (folderPerms[id] == null) {
        // Breadcrumb navigation: ask the server for our mask on that folder.
        try {
          const r = await api(`/api/files/info?id=${id}`).then((r) => r.json());
          folderPerms[id] = r.entry.permissions;
        } catch (_) {
          folderPerms[id] = PERM_ALL;
        }
      }
    }
    loadFiles(id).catch((e) => alert(e.message));
  }

  async function newFolder() {
    const name = prompt("New folder name:");
    if (!name || !name.trim()) return;
    try {
      await api("/api/files/folder", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ parent_id: currentParent, name: name.trim() }),
      });
      await loadFiles(currentParent);
    } catch (e) {
      alert(e.message);
    }
  }

  async function newFile() {
    let name = prompt("New file name:", "note.md");
    if (name === null) return; // cancelled
    name = name.trim();
    if (!name) return;
    // Only text-ish extensions — anything else needs an upload.
    const dot = name.lastIndexOf(".");
    const ext = dot >= 0 ? name.slice(dot + 1).toLowerCase() : "";
    const editable =
      PREVIEW_EXT.text.indexOf(ext) >= 0 || ext === "md" || ext === "markdown";
    if (!editable) {
      alert(
        "Only text files can be created here (.txt, .md, .csv, code, ...).\n" +
          "Upload other file types instead.",
      );
      return;
    }
    try {
      const res = await api("/api/files/file", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ parent_id: currentParent, name: name }),
      }).then((r) => r.json());
      await loadFiles(currentParent);
      openPreview(res.entry); // text files open straight in the editor
    } catch (e) {
      alert(e.message);
    }
  }

  async function renameEntry(id, currentName) {
    const name = prompt("Rename to:", currentName);
    if (!name || !name.trim() || name.trim() === currentName) return;
    try {
      await api("/api/files/rename", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, name: name.trim() }),
      });
      await loadFiles(currentParent);
    } catch (e) {
      alert(e.message);
    }
  }

  async function deleteEntry(id, isDir, name) {
    const promptText = isDir
      ? `Delete folder "${name}" and everything inside it?`
      : `Delete file "${name}"?`;
    if (!confirm(promptText)) return;
    try {
      // Same endpoint as the bulk bar — a single item is a batch of one.
      const res = await api("/api/files/batch/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids: [id] }),
      });
      reportOutcome(await res.json());
      await loadFiles(currentParent);
    } catch (e) {
      alert(e.message);
    }
  }

  function downloadFile(id, name) {
    // Trigger a browser download via a temporary anchor.
    const a = document.createElement("a");
    a.href = `/api/files/download?id=${id}`;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  // ---------- file preview (lightbox) ----------
  const previewModal = document.getElementById("preview-modal");

  // Extensions the browser renders natively, mirroring `extension_type()` in
  // src/web/routes/files.rs. The server stays the authority on the actual
  // Content-Type; this list only decides what a click opens.
  const PREVIEW_EXT = {
    image: ["png", "jpg", "jpeg", "gif", "webp", "avif", "bmp", "ico", "apng", "svg"],
    video: ["mp4", "webm", "ogv", "mov", "m4v"],
    audio: ["mp3", "wav", "ogg", "oga", "opus", "m4a", "aac", "flac"],
    pdf: ["pdf"],
    html: ["html", "htm"],
    text: [
      "txt", "text", "md", "markdown", "csv", "tsv", "log", "json", "xml",
      "yml", "yaml", "toml", "ini", "cfg", "conf", "env", "sql", "rst",
      "tex", "diff", "patch", "rs", "js", "mjs", "cjs", "jsx", "ts", "tsx",
      "py", "rb", "go", "java", "c", "h", "cc", "cpp", "hpp", "cs", "php",
      "sh", "bash", "zsh", "pl", "lua", "swift", "kt", "kts", "scala", "r",
      "vue", "svelte", "css", "scss", "sass", "less",
    ],
  };

  function previewKind(name) {
    const dot = name.lastIndexOf(".");
    if (dot < 0) return null;
    const ext = name.slice(dot + 1).toLowerCase();
    for (const kind of Object.keys(PREVIEW_EXT)) {
      if (PREVIEW_EXT[kind].indexOf(ext) >= 0) return kind;
    }
    return null;
  }

  function openPreview(entry) {
    const kind = previewKind(entry.name);
    if (!kind || entry.is_dir) return;
    document.getElementById("preview-name").textContent = entry.name;
    const src = `/api/files/preview?id=${entry.id}`;
    document.getElementById("preview-newtab").href = src;

    const body = document.getElementById("preview-body");
    body.innerHTML = "";
    if (kind === "text") {
      // Text-ish files open in the editor instead of a plain frame.
      body.style.display = "none";
      editorRoot.style.display = "flex";
      openEditor(entry);
      return;
    }
    closeEditor();
    body.style.display = "";
    let el;
    if (kind === "image") {
      el = document.createElement("img");
      el.src = src;
      el.alt = entry.name;
    } else if (kind === "video") {
      el = document.createElement("video");
      el.controls = true;
      el.src = src;
    } else if (kind === "audio") {
      el = document.createElement("audio");
      el.controls = true;
      el.src = src;
    } else {
      // PDF (the browser's own viewer), HTML (sandboxed server-side) and
      // text all render fine in a plain frame.
      el = document.createElement("iframe");
      el.src = src;
      el.title = entry.name;
    }
    el.className = `preview-${kind}`;
    if (kind === "image" || kind === "video" || kind === "audio") {
      el.addEventListener("error", () => {
        body.innerHTML = "";
        const msg = document.createElement("div");
        msg.className = "empty-small";
        msg.textContent = "Preview failed - the file may be unavailable. Use Download instead.";
        body.appendChild(msg);
      });
    }
    body.appendChild(el);
    previewModal.style.display = "flex";
  }

  function closePreview() {
    // An edited file keeps its changes until the user says otherwise.
    if (editorEntry && editorDirty() && !confirm("Discard unsaved changes?")) return;
    previewModal.style.display = "none";
    const body = document.getElementById("preview-body");
    body.innerHTML = "";
    body.style.display = "";
    closeEditor();
  }

  // ---------- text editor (inside the lightbox) ----------
  const editorRoot = document.getElementById("editor-root");
  const editorText = document.getElementById("editor-text");
  const editorStatus = document.getElementById("editor-status");
  const editorMeta = document.getElementById("editor-meta");
  const editorMdToggle = document.getElementById("editor-md-toggle");
  const editorMdPane = document.getElementById("editor-md");
  let editorEntry = null; // file open in the editor
  let editorBaseline = ""; // content as loaded/saved (dirty check)
  let editorIsMd = false;
  let editorMdOn = true; // preview pane on/off, remembered across opens

  function editorDirty() {
    return editorEntry !== null && editorText.value !== editorBaseline;
  }

  function setEditorStatus(text) {
    editorStatus.textContent = text;
    editorStatus.classList.toggle("unsaved", text === "* unsaved");
  }

  function updateEditorMeta() {
    const lines = editorText.value === "" ? 1 : editorText.value.split("\n").length;
    editorMeta.textContent = `${lines} lines, ${editorText.value.length} chars`;
  }

  function setEditorMdVisible(on) {
    editorMdPane.style.display = on ? "" : "none";
    editorMdToggle.setAttribute("aria-pressed", String(on));
    editorMdToggle.classList.toggle("active", on);
    if (on) renderMarkdown();
  }

  function openEditor(entry) {
    editorEntry = entry;
    previewModal.style.display = "flex";
    editorIsMd = /\.(md|markdown)$/i.test(entry.name);
    editorText.value = "";
    editorBaseline = "";
    setEditorStatus("loading...");
    updateEditorMeta();
    editorMdToggle.style.display = editorIsMd ? "" : "none";
    setEditorMdVisible(editorIsMd && editorMdOn);
    api(`/api/files/preview?id=${entry.id}`)
      .then((r) => r.text())
      .then((text) => {
        if (editorEntry !== entry) return; // another file opened meanwhile
        editorText.value = text;
        editorBaseline = text;
        setEditorStatus("");
        updateEditorMeta();
        if (editorMdPane.style.display !== "none") renderMarkdown();
        editorText.focus();
      })
      .catch((e) => setEditorStatus(`load failed: ${e.message}`));
  }

  function closeEditor() {
    editorEntry = null;
    editorBaseline = "";
    editorText.value = "";
    editorRoot.style.display = "none";
    editorMdPane.innerHTML = "";
    setEditorStatus("");
  }

  function saveEditor() {
    if (!editorEntry) return;
    const entry = editorEntry;
    const content = editorText.value;
    setEditorStatus("saving...");
    api(`/api/files/content?id=${entry.id}`, {
      method: "PUT",
      headers: { "Content-Type": "text/plain; charset=utf-8" },
      body: content,
    })
      .then((r) => r.json())
      .then((res) => {
        if (editorEntry !== entry) return;
        editorBaseline = content;
        setEditorStatus("saved");
        window.setTimeout(() => {
          if (editorStatus.textContent === "saved") setEditorStatus("");
        }, 2000);
        if (res.entry) {
          // The listing behind the dialog shows the new size/modified_at.
          entry.size = res.entry.size;
          entry.modified_at = res.entry.modified_at;
          openFolder(currentParent);
        }
        updateEditorMeta();
      })
      .catch((e) => setEditorStatus(`save failed: ${e.message}`));
  }

  // Mini Markdown renderer for the preview pane. Everything is HTML-escaped
  // before the transformations run and link/image targets are restricted to
  // http(s) and relative URLs, so a note can never run script in this origin.
  function mdToHtml(src) {
    const esc = (s) =>
      s.replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
    const safeUrl = (u) => (/^(https?:\/\/|\/|#)/i.test(u.trim()) ? u.trim() : "#");
    const inline = (s) => {
      let out = esc(s);
      // Code spans first: their content must survive every other rule.
      const codes = [];
      out = out.replace(/`([^`]+)`/g, (_, c) => {
        codes.push(c);
        return `\uE000${codes.length - 1}\uE000`;
      });
      out = out
        .replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, (_, alt, url) => {
          const src2 = safeUrl(url);
          if (src2 === "#") return alt;
          return `<img src="${src2}" alt="${alt}">`;
        })
        .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, text, url) =>
          `<a href="${safeUrl(url)}" target="_blank" rel="noopener noreferrer">${text}</a>`,
        )
        .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
        .replace(/\*([^*]+)\*/g, "<em>$1</em>")
        .replace(/~~([^~]+)~~/g, "<del>$1</del>");
      return out.replace(/\uE000(\d+)\uE000/g, (_, i) => `<code>${codes[+i]}</code>`);
    };
    const lines = src.replace(/\r\n?/g, "\n").split("\n");
    let html = "";
    let para = [];
    let listType = null; // "ul" | "ol" while a list is open
    let quote = [];
    let fence = null; // accumulated content of an open ``` block
    const closePara = () => {
      if (para.length) {
        html += `<p>${para.join("<br>")}</p>`;
        para = [];
      }
    };
    const closeList = () => {
      if (listType) {
        html += `</${listType}>`;
        listType = null;
      }
    };
    const closeQuote = () => {
      if (quote.length) {
        html += `<blockquote>${quote.join("<br>")}</blockquote>`;
        quote = [];
      }
    };
    for (const raw of lines) {
      if (fence !== null) {
        if (/^\s*```/.test(raw)) {
          html += `<pre><code>${esc(fence.join("\n"))}</code></pre>`;
          fence = null;
        } else {
          fence.push(raw);
        }
        continue;
      }
      if (/^\s*```/.test(raw)) {
        closePara();
        closeList();
        closeQuote();
        fence = [];
        continue;
      }
      if (/^\s*$/.test(raw)) {
        closePara();
        closeList();
        closeQuote();
        continue;
      }
      const heading = raw.match(/^(#{1,6})\s+(.*)$/);
      if (heading) {
        closePara();
        closeList();
        closeQuote();
        const level = heading[1].length;
        html += `<h${level}>${inline(heading[2])}</h${level}>`;
        continue;
      }
      if (/^\s*(-{3,}|\*{3,}|_{3,})\s*$/.test(raw)) {
        closePara();
        closeList();
        closeQuote();
        html += "<hr>";
        continue;
      }
      const quoted = raw.match(/^>\s?(.*)$/);
      if (quoted) {
        closePara();
        closeList();
        quote.push(inline(quoted[1]));
        continue;
      }
      const ulItem = raw.match(/^\s*[-*+]\s+(.*)$/);
      const olItem = raw.match(/^\s*\d+\.\s+(.*)$/);
      if (ulItem || olItem) {
        closePara();
        closeQuote();
        const want = ulItem ? "ul" : "ol";
        if (listType !== want) {
          closeList();
          html += `<${want}>`;
          listType = want;
        }
        html += `<li>${inline((ulItem || olItem)[1])}</li>`;
        continue;
      }
      closeList();
      closeQuote();
      para.push(inline(raw));
    }
    if (fence !== null) html += `<pre><code>${esc(fence.join("\n"))}</code></pre>`;
    closePara();
    closeList();
    closeQuote();
    return html;
  }

  function renderMarkdown() {
    editorMdPane.innerHTML = mdToHtml(editorText.value);
  }

  let mdRenderTimer = null;
  editorText.addEventListener("input", () => {
    if (editorEntry === null) return;
    setEditorStatus(editorDirty() ? "* unsaved" : "");
    updateEditorMeta();
    if (editorIsMd && editorMdPane.style.display !== "none") {
      window.clearTimeout(mdRenderTimer);
      mdRenderTimer = window.setTimeout(renderMarkdown, 150);
    }
  });
  editorText.addEventListener("keydown", (e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const start = editorText.selectionStart;
      const end = editorText.selectionEnd;
      if (e.shiftKey) {
        // Unindent the current line by up to two spaces.
        const value = editorText.value;
        const lineStart = value.lastIndexOf("\n", start - 1) + 1;
        const drop = value.slice(lineStart, lineStart + 2) === "  " ? 2 : 0;
        if (drop) {
          editorText.value = value.slice(0, lineStart) + value.slice(lineStart + drop);
          editorText.selectionStart = Math.max(lineStart, start - drop);
          editorText.selectionEnd = end - drop;
          editorText.dispatchEvent(new Event("input"));
        }
      } else {
        editorText.setRangeText("  ", start, end, "end");
        editorText.dispatchEvent(new Event("input"));
      }
    } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      saveEditor();
    }
  });
  document.getElementById("editor-save-btn").addEventListener("click", saveEditor);
  editorMdToggle.addEventListener("click", () => {
    editorMdOn = !editorMdOn;
    setEditorMdVisible(editorIsMd && editorMdOn);
  });

  // ---------- upload (files, folders, drag & drop) ----------
  const statusEl = document.getElementById("upload-status");

  function setUploadStatus(text) {
    if (text == null) {
      statusEl.style.display = "none";
      statusEl.textContent = "";
    } else {
      statusEl.style.display = "";
      statusEl.textContent = text;
    }
  }

  // Flatten a dropped FileSystemEntry tree into items:
  //   {file, path} for files (path = "Top/Sub/name.txt"), and
  //   {dir,  path} for folders — so empty folders get created too.
  function flattenEntry(entry, prefix) {
    return new Promise((resolve) => {
      if (entry.isFile) {
        entry.file(
          (file) => resolve([{ file, path: prefix + entry.name }]),
          () => resolve([])
        );
        return;
      }
      if (!entry.isDirectory) {
        resolve([]);
        return;
      }
      const path = prefix + entry.name;
      const reader = entry.createReader();
      // readEntries yields at most ~100 entries per call — loop until empty.
      const readAll = () =>
        new Promise((res) => reader.readEntries((batch) => res(batch), () => res([])));
      (async () => {
        const out = [{ dir: path }];
        let batch;
        do {
          batch = await readAll();
          for (const child of batch) {
            out.push(...(await flattenEntry(child, path + "/")));
          }
        } while (batch.length > 0);
        resolve(out);
      })();
    });
  }

  // Walk `dirPath` from the upload root, ensuring each level exists.
  // Returns the folder id, `null` for the root itself, or `undefined` on
  // failure (the message is pushed into `failures`; the subtree is skipped).
  async function ensurePath(base, dirPath, cache, failures, failedDirs) {
    const parts = dirPath.split("/").filter(Boolean);
    let parentId = base;
    let acc = "";
    for (const seg of parts) {
      acc = acc ? acc + "/" + seg : seg;
      if (failedDirs.has(acc)) return undefined;
      if (cache.has(acc)) {
        parentId = cache.get(acc);
        continue;
      }
      try {
        const res = await api("/api/files/folder/ensure", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ parent_id: parentId, name: seg }),
        });
        const body = await res.json();
        parentId = body.entry.id;
        cache.set(acc, parentId);
      } catch (e) {
        failedDirs.add(acc);
        failures.push(`${acc}/ — ${e.message}`);
        return undefined;
      }
    }
    return parentId;
  }

  // Upload a prepared item list ({file,path} / {dir,path}), creating missing
  // folders on the way. One failing item never aborts the rest.
  async function uploadTree(items) {
    const files = items.filter((i) => i.file);
    if (items.length === 0) return;
    const base = currentParent; // null = own root
    const failures = [];
    const failedDirs = new Set();
    const cache = new Map([["", base]]);
    let done = 0;

    try {
      // Folders first so empty ones exist before files land.
      for (const item of items) {
        if (!item.dir) continue;
        await ensurePath(base, item.dir, cache, failures, failedDirs);
      }
      for (const item of files) {
        const parts = item.path.split("/").filter(Boolean);
        const fileName = parts.pop();
        const parentId = await ensurePath(base, parts.join("/"), cache, failures, failedDirs);
        if (parentId === undefined) continue; // reason already recorded
        setUploadStatus(`Uploading ${done + 1}/${files.length} — ${item.path}`);
        const fd = new FormData();
        fd.append("parent", parentId == null ? "" : String(parentId));
        fd.append("file", item.file, fileName);
        try {
          await api("/api/files/upload", { method: "POST", body: fd });
        } catch (e) {
          failures.push(`${item.path} — ${e.message}`);
        }
        done += 1;
      }
    } finally {
      setUploadStatus(null);
    }

    if (failures.length) {
      alert(
        `${failures.length} of ${files.length} item(s) could not be uploaded:\n\n` +
          failures.slice(0, 8).join("\n") +
          (failures.length > 8 ? "\n…" : "")
      );
    }
    await loadFiles(currentParent);
  }

  // Plain file list (file input or simple drop): webkitRelativePath covers
  // the folder-input case ("Top/Sub/name.txt"), plain files use file.name.
  async function uploadFiles(fileList) {
    const items = Array.from(fileList).map((f) => ({
      file: f,
      path: f.webkitRelativePath || f.name,
    }));
    await uploadTree(items);
  }

  // Drag & drop of files *and folders* into the dropzone.
  async function uploadDropped(dt) {
    // Snapshot entry handles synchronously — DataTransferItem accessors may
    // be invalidated once we go async.
    const entries = Array.from(dt.items || [])
      .map((it) => (typeof it.webkitGetAsEntry === "function" ? it.webkitGetAsEntry() : null))
      .filter(Boolean);
    if (entries.length > 0) {
      const flat = [];
      for (const entry of entries) {
        flat.push(...(await flattenEntry(entry, "")));
      }
      await uploadTree(flat);
    } else if (dt.files && dt.files.length) {
      // Browser without the entry API: plain files only.
      await uploadFiles(dt.files);
    }
  }

  // ---------- move / copy ----------
  const transferModal = document.getElementById("transfer-modal");
  let transfer = null; // { mode: "move"|"copy", entries: [...] }
  // Navigation stack inside the picker; starts at the user's root.
  let pickStack = [{ id: null, name: "Home" }];

  // Open the destination picker for one entry (row menu) or the whole
  // selection (bulk bar) — both go through the batch endpoints.
  function openTransferDialog(mode, entries) {
    transfer = { mode, entries };
    const what =
      entries.length === 1 ? `"${entries[0].name}"` : `${entries.length} items`;
    document.getElementById("transfer-title").textContent =
      (mode === "move" ? "Move " : "Copy ") + what + " to…";
    document.getElementById("transfer-confirm").textContent =
      mode === "move" ? "Move here" : "Copy here";
    pickStack = [{ id: null, name: "Home" }];
    transferModal.style.display = "flex";
    renderPick().catch((e) => alert(e.message));
  }

  function closeTransferDialog() {
    transferModal.style.display = "none";
    transfer = null;
  }

  function pickAt(idx) {
    pickStack = pickStack.slice(0, idx + 1);
    renderPick().catch((e) => alert(e.message));
  }

  async function renderPick() {
    const parent = pickStack[pickStack.length - 1].id;
    const url = parent == null ? "/api/files" : `/api/files?parent=${parent}`;
    const res = await api(url).then((r) => r.json());

    // Path strip: clickable crumbs up to the current folder.
    const crumbEl = document.getElementById("pick-crumb");
    crumbEl.innerHTML = "";
    pickStack.forEach((c, i) => {
      if (i > 0) {
        const sep = document.createElement("span");
        sep.className = "sep";
        sep.textContent = "›";
        crumbEl.appendChild(sep);
      }
      if (i === pickStack.length - 1) {
        const cur = document.createElement("span");
        cur.className = "current";
        cur.textContent = c.name;
        crumbEl.appendChild(cur);
      } else {
        const a = document.createElement("a");
        a.textContent = c.name;
        a.addEventListener("click", () => pickAt(i));
        crumbEl.appendChild(a);
      }
    });

    // Folder list (files are not valid destinations).
    const listEl = document.getElementById("pick-list");
    listEl.innerHTML = "";
    const dirs = res.entries.filter((e) => e.is_dir);
    if (dirs.length === 0) {
      listEl.innerHTML = '<div class="empty-small">No subfolders here.</div>';
      return;
    }
    for (const d of dirs) {
      const row = document.createElement("div");
      row.className = "pick-row";
      row.innerHTML =
        '<span class="icon folder">📁</span><span class="pick-name">' +
        escapeHtml(d.name) + "</span>" +
        (d.owner_name
          ? ' <span class="shared-badge">↔ ' + escapeHtml(d.owner_name) + "</span>"
          : "");
      row.addEventListener("click", () => {
        pickStack.push({ id: d.id, name: d.name });
        renderPick().catch((e) => alert(e.message));
      });
      listEl.appendChild(row);
    }
  }

  async function transferConfirm() {
    if (!transfer) return;
    const dest = pickStack[pickStack.length - 1];
    const endpoint =
      transfer.mode === "move" ? "/api/files/batch/move" : "/api/files/batch/copy";
    try {
      const res = await api(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ids: transfer.entries.map((e) => e.id),
          dest_parent: dest.id,
        }),
      });
      const out = await res.json();
      closeTransferDialog();
      // 409 (name exists), 403 (missing permission), 400 (into itself, …)
      reportOutcome(out);
      await loadFiles(currentParent);
    } catch (e) {
      alert(e.message);
    }
  }

  // ---------- bulk actions (operating on the selection) ----------
  function bulkTransfer(mode) {
    const entries = eligible((e) =>
      mode === "move" ? permsOf(e) & PERM_UPDATE : permsOf(e) & PERM_READ
    );
    if (entries.length === 0) {
      alert(
        `None of the selected items may be ${mode === "move" ? "moved" : "copied"}.`
      );
      return;
    }
    openTransferDialog(mode, entries);
  }

  function bulkDelete() {
    const entries = eligible((e) => permsOf(e) & PERM_DELETE);
    if (entries.length === 0) return;

    const files = entries.filter((e) => !e.is_dir);
    const dirs = entries.filter((e) => e.is_dir);
    let msg = `Delete ${entries.length} of ${selected.size} selected item(s)?`;
    if (files.length) {
      msg += `\n\n${files.length} file(s) · ${formatSize(
        files.reduce((sum, e) => sum + (e.size || 0), 0)
      )}`;
    }
    if (dirs.length) {
      msg += `\n${dirs.length} folder(s) · with everything inside them`;
    }
    msg += skippedNote(entries.length);
    if (!confirm(msg)) return;

    (async () => {
      try {
        const res = await api("/api/files/batch/delete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids: entries.map((e) => e.id) }),
        });
        reportOutcome(await res.json());
        await loadFiles(currentParent);
      } catch (e) {
        alert(e.message);
      }
    })();
  }

  // Pack the readable part of the selection into one ZIP on the server and
  // hand the download over to the browser.
  function bulkDownload() {
    const entries = eligible((e) => permsOf(e) & PERM_READ);
    if (entries.length === 0) return;

    (async () => {
      try {
        const res = await api("/api/files/zip", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids: entries.map((e) => e.id) }),
        });
        const body = await res.json();
        // Top-level navigation: the response is an attachment, not a page.
        window.location.href = `/api/files/zip?token=${encodeURIComponent(body.token)}`;
      } catch (e) {
        alert(e.message);
      }
    })();
  }

  function bulkShare() {
    const entries = eligible((e) => e.owner_id === meId);
    if (entries.length === 0) return;
    openShareDialog(entries);
  }

  // ---------- sharing ----------
  const shareModal = document.getElementById("share-modal");
  let shareEntries = []; // one entry (row menu) or the whole selection (bulk bar)

  function openShareDialog(entries) {
    shareEntries = entries;
    document.getElementById("share-title").textContent =
      entries.length === 1
        ? `Share "${entries[0].name}"`
        : `Share ${entries.length} items`;
    document
      .querySelectorAll("#perm-checks input")
      .forEach((cb) => (cb.checked = true));
    shareModal.style.display = "flex";

    // The grantee is picked from a dropdown of accounts — refetch every time
    // the dialog opens so freshly registered users show up immediately.
    loadShareTargets().catch(() => {
      const sel = document.getElementById("share-username");
      sel.innerHTML = "<option disabled>Cannot load users</option>";
      sel.disabled = true;
    });

    if (entries.length === 1) {
      // Existing shares only make sense item by item.
      loadShareList().catch((e) => alert(e.message));
    } else {
      document.getElementById("share-list").innerHTML =
        '<div class="empty-small">Every selected item gets the same share and permissions.</div>';
    }
  }

  function closeShareDialog() {
    shareModal.style.display = "none";
    shareEntries = [];
  }

  async function loadShareList() {
    const res = await api(`/api/shares/outgoing?file_id=${shareEntries[0].id}`).then(
      (r) => r.json()
    );
    const listEl = document.getElementById("share-list");
    listEl.innerHTML = "";
    if (res.shares.length === 0) {
      listEl.innerHTML = '<div class="empty-small">Not shared with anyone yet.</div>';
      return;
    }
    for (const s of res.shares) {
      const row = document.createElement("div");
      row.className = "share-row";
      const info = document.createElement("div");
      info.className = "share-info";
      info.innerHTML =
        '<span class="share-user">' + escapeHtml(s.username) + "</span>" +
        '<span class="share-perms">' + escapeHtml(s.permission_names.join(", ")) + "</span>";
      row.appendChild(info);
      const rm = document.createElement("button");
      rm.className = "danger";
      rm.textContent = "Remove";
      rm.addEventListener("click", async () => {
        try {
          await api(`/api/shares/${s.id}`, { method: "DELETE" });
          await loadShareList();
        } catch (e) {
          alert(e.message);
        }
      });
      row.appendChild(rm);
      listEl.appendChild(row);
    }
  }

  // Fill the grantee dropdown from the account list: sharing must not depend
  // on knowing the other user's name by heart. Only other accounts appear,
  // and ones that cannot sign in yet are marked as such.
  async function loadShareTargets() {
    const sel = document.getElementById("share-username");
    const users = await api("/api/users").then((r) => r.json());
    sel.innerHTML = "";
    if (users.length === 0) {
      const opt = document.createElement("option");
      opt.textContent = "No other users yet";
      opt.disabled = true;
      sel.appendChild(opt);
      sel.disabled = true;
      return;
    }
    sel.disabled = false;
    for (const u of users) {
      const opt = document.createElement("option");
      opt.value = u.username;
      const named = u.display_name && u.display_name !== u.username;
      opt.textContent =
        (named ? `${u.username} (${u.display_name})` : u.username) +
        (u.is_active ? "" : " — inactive");
      sel.appendChild(opt);
    }
  }

  async function shareAdd() {
    if (shareEntries.length === 0) return;
    const username = document.getElementById("share-username").value.trim();
    if (!username) return;
    let mask = 0;
    document
      .querySelectorAll("#perm-checks input")
      .forEach((cb) => {
        if (cb.checked) mask |= Number(cb.value);
      });
    try {
      // One request for the whole selection (a single item is just an array
      // of one, so both paths stay identical).
      const res = await api("/api/shares/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          file_ids: shareEntries.map((e) => e.id),
          username,
          permissions: mask,
        }),
      });
      const out = await res.json();
      if (shareEntries.length === 1) {
        await loadShareList();
      } else {
        document.getElementById("share-list").innerHTML =
          out.ok.length > 0
            ? `<div class="empty-small">${out.ok.length} of ${shareEntries.length} item(s) shared with ${escapeHtml(username)}.</div>`
            : '<div class="empty-small">Nothing was shared.</div>';
      }
      reportOutcome(out);
    } catch (e) {
      alert(e.message);
    }
  }

  async function logout() {
    try {
      await api("/api/logout", { method: "POST" });
    } catch (_) {}
    window.location.href = "/login";
  }

  // ---------- wire up ----------
  document.getElementById("new-folder-btn").addEventListener("click", newFolder);
  document.getElementById("new-file-btn").addEventListener("click", newFile);
  document.getElementById("upload-btn").addEventListener("click", () => fileInput.click());
  document.getElementById("upload-folder-btn").addEventListener("click", () =>
    folderInput.click()
  );
  document.getElementById("logout-btn").addEventListener("click", logout);
  // Share dialog.
  document.getElementById("share-add-btn").addEventListener("click", shareAdd);
  document.getElementById("share-close-btn").addEventListener("click", closeShareDialog);
  document.getElementById("share-username").addEventListener("keydown", (e) => {
    if (e.key === "Enter") shareAdd();
  });
  shareModal.addEventListener("click", (e) => {
    if (e.target === shareModal) closeShareDialog();
  });
  // Move/Copy destination picker.
  document.getElementById("transfer-cancel").addEventListener("click", closeTransferDialog);
  document.getElementById("transfer-confirm").addEventListener("click", transferConfirm);
  transferModal.addEventListener("click", (e) => {
    if (e.target === transferModal) closeTransferDialog();
  });
  // File preview (lightbox).
  document.getElementById("preview-close-btn").addEventListener("click", closePreview);
  previewModal.addEventListener("click", (e) => {
    if (e.target === previewModal) closePreview();
  });
  // Multi-selection: header checkbox selects the whole listing (deselecting
  // it clears everything, including a partial selection).
  document.getElementById("select-all").addEventListener("change", (e) => {
    const on = e.target.checked;
    currentEntries.forEach((entry) => setSelected(entry, on));
    lastCheckIndex = null;
    syncSelectionUi();
  });
  // Bulk action bar (shown while anything is selected).
  document.getElementById("bulk-download").addEventListener("click", bulkDownload);
  document.getElementById("bulk-move").addEventListener("click", () => bulkTransfer("move"));
  document.getElementById("bulk-copy").addEventListener("click", () => bulkTransfer("copy"));
  document.getElementById("bulk-share").addEventListener("click", bulkShare);
  document.getElementById("bulk-delete").addEventListener("click", bulkDelete);
  document.getElementById("bulk-clear").addEventListener("click", clearSelection);
  fileInput.addEventListener("change", () => {
    uploadFiles(fileInput.files);
    fileInput.value = "";
  });
  folderInput.addEventListener("change", () => {
    uploadFiles(folderInput.files);
    folderInput.value = "";
  });

  // Drag & drop upload.
  dropzone.addEventListener("click", () => fileInput.click());
  ["dragenter", "dragover"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    })
  );
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer) {
      uploadDropped(e.dataTransfer).catch((err) => alert(err.message));
    }
  });

  // ---------- init ----------
  loadMe()
    .then(() => loadFiles(currentParent))
    .catch((e) => {
      if (e.message !== "unauthorized") alert(e.message);
    });
})();
