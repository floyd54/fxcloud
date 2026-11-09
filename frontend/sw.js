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
 *
 * Scope - and this is the load-bearing part: ONLY same-origin static files
 * under /assets/ are passed through. Everything the product actually runs
 * on - API calls, downloads, page navigations, and blob: URLs such as the
 * decrypted PDF preview frame - never reaches this worker at all, so no
 * platform-specific quirk of respondWith() (Android Chrome's download and
 * PDF handling in particular) can ever attach to them. The passthrough on
 * static files exists so the fetch handler demonstrably handles a request;
 * it is byte-equivalent to the browser doing it (verified against a real
 * Chromium with fetch-event logging), and there is no Cache API call
 * anywhere below. The suite fails if this scope widens or if a caches.
 * reference appears.
 */
self.addEventListener("install", function () {
  self.skipWaiting();
});
self.addEventListener("activate", function (event) {
  event.waitUntil(self.clients.claim());
});
self.addEventListener("fetch", function (event) {
  var url;
  try {
    url = new URL(event.request.url);
  } catch (e) {
    return; // unparsable URL: browser's problem, not ours
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return; // blob:, data:, ...
  if (url.origin !== self.location.origin) return;
  if (url.pathname.indexOf("/assets/") !== 0) return;
  event.respondWith(fetch(event.request));
});
