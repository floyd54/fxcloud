(function () {
  "use strict";

  const rowsEl = document.getElementById("file-rows");
  const breadcrumbEl = document.getElementById("breadcrumb");
  const fileInput = document.getElementById("file-input");
  const dropzone = document.getElementById("dropzone");

  // Current folder id (null == root).
  let currentParent = null;
  // Viewer's permission mask in the current folder (root is always full).
  let currentPerms = 31;
  // Known permission masks per folder id (learned from listings/info calls).
  const folderPerms = {};
  // The signed-in user's id (to tell own items from shared ones).
  let meId = null;

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
    if (entries.length === 0) {
      rowsEl.innerHTML =
        '<tr><td colspan="4"><div class="empty"><div class="big">📂</div>' +
        "This folder is empty.<br/>Upload a file or create a folder to get started.</div></td></tr>";
      return;
    }

    for (const entry of entries) {
      const tr = document.createElement("tr");

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
      sizeTd.textContent = entry.is_dir ? "—" : formatSize(entry.size);

      const dateTd = document.createElement("td");
      dateTd.className = "date-col";
      dateTd.textContent = formatDate(entry.modified_at);

      const actionsTd = document.createElement("td");
      actionsTd.className = "actions-col";

      const actions = document.createElement("div");
      actions.className = "actions";

      const perms = entry.permissions == null ? PERM_ALL : entry.permissions;
      const isOwner = entry.owner_id === meId;

      if (!entry.is_dir && (perms & PERM_READ)) {
        const dl = document.createElement("button");
        dl.textContent = "Download";
        dl.addEventListener("click", (e) => {
          e.stopPropagation();
          downloadFile(entry.id, entry.name);
        });
        actions.appendChild(dl);
      }

      // Re-sharing (PERM_SHARE bit) needs cascading shares on the backend;
      // for now only the owner manages an item's shares.
      if (isOwner) {
        const sh = document.createElement("button");
        sh.textContent = "Share";
        sh.addEventListener("click", (e) => {
          e.stopPropagation();
          openShareDialog(entry);
        });
        actions.appendChild(sh);
      }

      if (perms & PERM_UPDATE) {
        const ren = document.createElement("button");
        ren.textContent = "Rename";
        ren.addEventListener("click", (e) => {
          e.stopPropagation();
          renameEntry(entry.id, entry.name);
        });
        actions.appendChild(ren);
      }

      if (perms & PERM_DELETE) {
        const del = document.createElement("button");
        del.className = "danger";
        del.textContent = "Delete";
        del.addEventListener("click", (e) => {
          e.stopPropagation();
          deleteEntry(entry.id, entry.is_dir, entry.name);
        });
        actions.appendChild(del);
      }

      actionsTd.appendChild(actions);

      tr.appendChild(nameTd);
      tr.appendChild(sizeTd);
      tr.appendChild(dateTd);
      tr.appendChild(actionsTd);

      if (entry.is_dir) {
        tr.addEventListener("click", () => openFolder(entry.id, perms));
      }

      rowsEl.appendChild(tr);
    }
  }

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
    renderRows(listRes.entries);
    currentPerms =
      parent == null || folderPerms[parent] == null ? PERM_ALL : folderPerms[parent];
    renderToolbar();
  }

  // Show the create toolbar only where the viewer holds CREATE.
  function renderToolbar() {
    const canCreate = (currentPerms & PERM_CREATE) !== 0;
    const folderBtn = document.getElementById("new-folder-btn");
    const uploadBtn = document.getElementById("upload-btn");
    folderBtn.style.display = canCreate ? "" : "none";
    uploadBtn.style.display = canCreate ? "" : "none";
    dropzone.style.display = canCreate ? "" : "none";
  }

  async function loadMe() {
    const res = await api("/api/me").then((r) => r.json());
    meId = res.id;
    document.getElementById("user-label").textContent =
      res.display_name || res.username;
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
      await api("/api/files/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
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

  async function uploadFiles(fileList) {
    const files = Array.from(fileList);
    if (files.length === 0) return;

    for (const file of files) {
      const fd = new FormData();
      fd.append("parent", currentParent == null ? "" : String(currentParent));
      fd.append("file", file, file.name);
      try {
        await api("/api/files/upload", { method: "POST", body: fd });
      } catch (e) {
        alert(`Failed to upload "${file.name}": ${e.message}`);
      }
    }
    await loadFiles(currentParent);
  }

  // ---------- sharing ----------
  const shareModal = document.getElementById("share-modal");
  let shareTarget = null; // entry being shared

  function openShareDialog(entry) {
    shareTarget = entry;
    document.getElementById("share-title").textContent = `Share "${entry.name}"`;
    document.getElementById("share-username").value = "";
    document
      .querySelectorAll("#perm-checks input")
      .forEach((cb) => (cb.checked = true));
    shareModal.style.display = "flex";
    loadShareList().catch((e) => alert(e.message));
  }

  function closeShareDialog() {
    shareModal.style.display = "none";
    shareTarget = null;
  }

  async function loadShareList() {
    const res = await api(`/api/shares/outgoing?file_id=${shareTarget.id}`).then(
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

  async function shareAdd() {
    if (!shareTarget) return;
    const username = document.getElementById("share-username").value.trim();
    if (!username) return;
    let mask = 0;
    document
      .querySelectorAll("#perm-checks input")
      .forEach((cb) => {
        if (cb.checked) mask |= Number(cb.value);
      });
    try {
      await api("/api/shares", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_id: shareTarget.id, username, permissions: mask }),
      });
      document.getElementById("share-username").value = "";
      await loadShareList();
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
  document.getElementById("upload-btn").addEventListener("click", () => fileInput.click());
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
  fileInput.addEventListener("change", () => {
    uploadFiles(fileInput.files);
    fileInput.value = "";
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
    if (e.dataTransfer && e.dataTransfer.files.length) {
      uploadFiles(e.dataTransfer.files);
    }
  });

  // ---------- init ----------
  loadMe()
    .then(() => loadFiles(currentParent))
    .catch((e) => {
      if (e.message !== "unauthorized") alert(e.message);
    });
})();
