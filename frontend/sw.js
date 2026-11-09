/*
 * fxcloud service worker.
 *
 * Why it exists: browsers offer "Install app" (the PWA install prompt) only
 * when the page registers a service worker, so this one is what makes the
 * home-screen install possible. What it deliberately does NOT do is cache:
 *
 * - Every response here is session-dependent, and this app's discipline is
 *   "no cached response body" (ENCRYPTION.md section 11): file bytes,
 *   listings and key material must not sit in Cache Storage on someone's
 *   disk behind a service worker's back.
 * - The frontend ships without fingerprinted filenames and is served with
 *   no-cache on purpose; a shell cached here would pin an installed app to
 *   old JS after a release while everyone else already moved on.
 * - An end-to-end encrypted cloud client without a network has nothing
 *   truthful to show - the browser's own offline page is the honest
 *   answer, not a stale shell with buttons that only fail.
 *
 * So every request passes straight through: behaviour is byte-identical to
 * having no worker at all, only the install offer changes. skipWaiting and
 * clients.claim keep the worker from demanding an extra reload, which also
 * keeps it invisible.
 */
self.addEventListener("install", function () {
  self.skipWaiting();
});
self.addEventListener("activate", function (event) {
  event.waitUntil(self.clients.claim());
});
self.addEventListener("fetch", function (event) {
  // Same-origin only: anything else (the office iframe, cross-origin
  // links) keeps the browser's native handling and never touches this
  // worker's CSP. For our own requests respondWith(fetch()) is a pure
  // passthrough - no cache API call anywhere above, so what the browser
  // receives is what a page without a worker would receive.
  if (new URL(event.request.url).origin !== self.location.origin) return;
  event.respondWith(fetch(event.request));
});
