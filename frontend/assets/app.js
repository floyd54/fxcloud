(function () {
  "use strict";

  const rowsEl = document.getElementById("file-rows");
  const breadcrumbEl = document.getElementById("breadcrumb");
  const fileInput = document.getElementById("file-input");
  const dropzone = document.getElementById("dropzone");

  // Current folder id (null == root).
  let currentParent = null;

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

      if (!entry.is_dir) {
        const dl = document.createElement("button");
        dl.textContent = "Download";
        dl.addEventListener("click", (e) => {
          e.stopPropagation();
          downloadFile(entry.id, entry.name);
        });
        actions.appendChild(dl);
      }

      const ren = document.createElement("button");
      ren.textContent = "Rename";
      ren.addEventListener("click", (e) => {
        e.stopPropagation();
        renameEntry(entry.id, entry.name);
      });
      actions.appendChild(ren);

      const del = document.createElement("button");
      del.className = "danger";
      del.textContent = "Delete";
      del.addEventListener("click", (e) => {
        e.stopPropagation();
        deleteEntry(entry.id, entry.is_dir, entry.name);
      });
      actions.appendChild(del);

      actionsTd.appendChild(actions);

      tr.appendChild(nameTd);
      tr.appendChild(sizeTd);
      tr.appendChild(dateTd);
      tr.appendChild(actionsTd);

      if (entry.is_dir) {
        tr.addEventListener("click", () => openFolder(entry.id));
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
  }

  async function loadMe() {
    const res = await api("/api/me").then((r) => r.json());
    document.getElementById("user-label").textContent =
      res.display_name || res.username;
  }

  // ---------- actions ----------
  function openFolder(id) {
    currentParent = id;
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
