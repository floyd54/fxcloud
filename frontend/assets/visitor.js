/**
 * Public-link visitor page (concepts/public_links.md section 7).
 *
 * A self-contained shell for a stranger who holds a bearer token: no
 * session, no login redirect, no account. The token lives in the path
 * (/s/<token>) and is the only credential - every request under
 * /api/public/<token>/... is gated by the server's per-IP budgets, so this
 * script never needs to (and must not) do anything clever with it.
 */
"use strict";
(function () {
  // ---- link token, from the path the server routed us on ----
  var TOKEN = (location.pathname.match(/^\/s\/(.+)$/) || [, ""])[1];
  var BASE = "/api/public/" + encodeURIComponent(TOKEN);
  var sourceId = null;        // the linked folder/file, from /meta
  var canRead = false;        // preset may list and download (READ)
  var canCreate = false;
  var canDelete = false;
  var isDir = true;           // false: the link points at a single file
  var crumb = [];             // navigation stack: [{id, name}]

  // ---- tiny helpers (mirrors app.js, minus the login redirect) ----
  function t(key, params) {
    return globalThis.I18N ? globalThis.I18N.t(key, params) : key;
  }
  function dateLocale() {
    return globalThis.I18N ? globalThis.I18N.dateLocale() : undefined;
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function formatSize(bytes) {
    if (bytes === 0) return "0 B";
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = Math.floor(Math.log(bytes) / Math.log(1024));
    var value = bytes / Math.pow(1024, i);
    return value.toFixed(i === 0 ? 0 : 1) + " " + units[i];
  }
  function formatDate(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d)) return "";
    return d.toLocaleString(dateLocale(), {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  }

  /**
   * One request against the visitor API. Unlike app.js this never bounces
   * to /login: a 404/410 here is the *point* (a dead link), and a 401
   * would mean the server revoked the token mid-session - show it, don't
   * redirect a stranger to a login form they have no use for.
   */
  async function api(url, options) {
    var res = await fetch(url, options);
    if (!res.ok) {
      var body = null;
      try { body = await res.json(); } catch (_) { /* not JSON */ }
      var message;
      if (body && body.code === "gone") message = t("visitor.expired");
      else if (body && body.code === "not_found") message = t("visitor.notFound");
      else if (body && body.code === "rate_limited") {
        message = body.error || t("err.request_failed", { status: res.status });
      } else if (body && body.error) message = body.error;
      else message = t("err.request_failed", { status: res.status });
      var err = new Error(message);
      err.status = res.status;
      err.code = body && body.code;
      throw err;
    }
    return res;
  }

  function $(id) { return document.getElementById(id); }

  function setStatus(msg, isError) {
    var el = $("v-status");
    el.textContent = msg;
    el.classList.toggle("error", !!isError);
    el.classList.remove("visitor-hidden");
    $("v-body").classList.add("visitor-hidden");
  }
  function clearStatus() {
    $("v-status").classList.add("visitor-hidden");
    $("v-body").classList.remove("visitor-hidden");
  }

  // ---- render ----
  function renderCrumb() {
    var el = $("v-crumb");
    if (crumb.length <= 1) { el.innerHTML = ""; return; }
    var html = "";
    crumb.forEach(function (node, i) {
      if (i > 0) html += '<span class="sep">/</span>';
      if (i === crumb.length - 1) {
        html += '<span class="current">' + escapeHtml(node.name) + "</span>";
      } else {
        html += '<a data-idx="' + i + '">' + escapeHtml(node.name) + "</a>";
      }
    });
    el.innerHTML = html;
    el.querySelectorAll("a").forEach(function (a) {
      a.addEventListener("click", function () {
        var idx = parseInt(a.getAttribute("data-idx"), 10);
        crumb = crumb.slice(0, idx + 1);
        loadList();
      });
    });
    $("v-up").classList.toggle("visitor-hidden", crumb.length <= 1);
  }

  function renderList(entries) {
    var list = $("v-list");
    list.innerHTML = "";
    if (entries.length === 0) {
      list.innerHTML = '<div class="visitor-row"><span class="v-name" style="cursor:default">'
        + escapeHtml(t("visitor.empty")) + "</span></div>";
      return;
    }
    for (var i = 0; i < entries.length; i++) {
      (function (e) {
        var row = document.createElement("div");
        row.className = "visitor-row";

        var icon = document.createElement("span");
        icon.className = "v-icon";
        icon.textContent = e.is_dir ? "\uD83D\uDCC1" : "\uD83D\uDCC4"; // folder / page
        row.appendChild(icon);

        var name = document.createElement("span");
        name.className = "v-name";
        name.textContent = e.name;
        name.addEventListener("click", function () {
          if (e.is_dir) {
            crumb.push({ id: e.id, name: e.name });
            loadList();
          } else {
            download(e.id);
          }
        });
        row.appendChild(name);

        if (!e.is_dir) {
          var size = document.createElement("span");
          size.className = "v-size";
          size.textContent = formatSize(e.size || 0);
          row.appendChild(size);
        }

        if (canDelete) {
          var del = document.createElement("button");
          del.className = "btn danger";
          del.style.padding = "4px 9px";
          del.style.fontSize = "12px";
          del.textContent = t("visitor.delete");
          del.addEventListener("click", function () {
            if (confirm(t("visitor.deleteConfirm", { name: e.name }))) removeEntry(e.id);
          });
          row.appendChild(del);
        }

        list.appendChild(row);
      })(entries[i]);
    }
  }

  // A link without READ (the add preset) or onto a single file has no
  // listing to ask for: calling /list anyway would answer 403/400 and
  // paint the page as an error. Show the entry itself - its name is
  // already disclosed by /meta - plus the one verb the preset allows.
  function renderPlain() {
    renderCrumb();
    var list = $("v-list");
    list.innerHTML = "";
    var row = document.createElement("div");
    row.className = "visitor-row";
    var icon = document.createElement("span");
    icon.className = "v-icon";
    icon.textContent = isDir ? "\uD83D\uDCC1" : "\uD83D\uDCC4";
    row.appendChild(icon);
    var name = document.createElement("span");
    name.className = "v-name";
    name.textContent = crumb[crumb.length - 1].name;
    row.appendChild(name);
    if (!isDir && canRead) {
      var dl = document.createElement("button");
      dl.className = "btn";
      dl.style.padding = "4px 9px";
      dl.style.fontSize = "12px";
      dl.textContent = t("visitor.download");
      dl.addEventListener("click", function () { download(sourceId); });
      row.appendChild(dl);
    }
    list.appendChild(row);
    clearStatus();
  }

  // ---- data ----
  async function loadMeta() {
    var res = await api(BASE + "/meta");
    var meta = await res.json();
    sourceId = meta.id;
    canRead = !!meta.can_read;
    canCreate = !!meta.can_create;
    canDelete = !!meta.can_delete;
    isDir = !!meta.is_dir;
    document.title = meta.name;
    $("v-title").textContent = meta.name;
    if (meta.label) $("v-label").textContent = meta.label;
    // A file link has no folder to drop into, an add link cannot browse:
    // the upload button follows CREATE *and* a folder source.
    $("v-upload-btn").classList.toggle("visitor-hidden", !canCreate || !isDir);
    crumb = [{ id: meta.id, name: meta.name }];
  }

  async function loadList() {
    var id = crumb[crumb.length - 1].id;
    var res = await api(BASE + "/list?id=" + encodeURIComponent(id));
    var data = await res.json();
    renderCrumb();
    renderList(data.entries || []);
    clearStatus();
  }

  function download(id) {
    // A temporary anchor: the response is an attachment, so a plain
    // navigation would work too, but this keeps the visitor on the page.
    var a = document.createElement("a");
    a.href = BASE + "/download?id=" + encodeURIComponent(id);
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  async function removeEntry(id) {
    try {
      await api(BASE + "/entry?id=" + encodeURIComponent(id), { method: "DELETE" });
      await loadList();
    } catch (e) {
      alert(e.message);
    }
  }

  async function uploadFile(file) {
    var fd = new FormData();
    fd.append("parent", String(crumb[crumb.length - 1].id));
    fd.append("file", file, file.name);
    try {
      await api(BASE + "/upload", { method: "POST", body: fd });
      // An add-only visitor never sees a listing - nothing to refresh.
      if (isDir && canRead) await loadList();
      else clearStatus();
    } catch (e) {
      alert(e.message);
    }
  }

  // ---- language switching (same event the rest of the UI fires) ----
  function repaint() {
    $("v-title").textContent = crumb.length
      ? crumb[crumb.length - 1].name
      : t("visitor.root");
    if (document.documentElement) document.documentElement.lang =
      globalThis.I18N && globalThis.I18N.currentCode ? globalThis.I18N.currentCode : "en";
    // Re-render the list so per-row buttons re-translate; the crumb and
    // toolbar labels are stamped by the data-i18n pass below.
    applyDataI18n();
    if (crumb.length) {
      if (isDir && canRead) loadList().catch(function () {});
      else renderPlain();
    }
  }

  function applyDataI18n() {
    document.querySelectorAll("[data-i18n]").forEach(function (el) {
      var key = el.getAttribute("data-i18n");
      var text = t(key);
      if (text !== key) el.textContent = text;
    });
    document.querySelectorAll("[data-i18n-title]").forEach(function (el) {
      var key = el.getAttribute("data-i18n-title");
      var text = t(key);
      if (text !== key) el.title = text;
    });
  }

  // ---- boot ----
  async function boot() {
    applyDataI18n();
    document.addEventListener("fxcloud:langchange", repaint);

    $("v-up").addEventListener("click", function () {
      if (crumb.length > 1) { crumb.pop(); loadList(); }
    });
    $("v-upload-btn").addEventListener("click", function () { $("v-file").click(); });
    $("v-file").addEventListener("change", function (ev) {
      var f = ev.target.files && ev.target.files[0];
      if (f) uploadFile(f);
      ev.target.value = "";
    });

    try {
      await loadMeta();
      if (isDir && canRead) await loadList();
      else renderPlain();
    } catch (e) {
      setStatus(e.message, true);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
