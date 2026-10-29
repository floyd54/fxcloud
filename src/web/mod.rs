pub mod routes;
pub mod state;
pub mod ui;

use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::routing::{any, get, post, put};
use axum::Router;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;

use self::state::SharedState;

/// The app-wide Content-Security-Policy (Audit.md F2).
///
/// The pages are self-contained - every script and stylesheet is an embedded
/// asset - so `default-src 'self'` already covers most of the surface:
///
/// * `script-src 'self' 'wasm-unsafe-eval'` - the only scripts are the
///   embedded ones. `'wasm-unsafe-eval'` is not a hole for JS; it exists
///   solely because the client-side Argon2id runs through
///   `hashwasm-argon2.js`, and WebAssembly compilation is gated on this
///   token (browsers that predate it ignore it *and* gate WASM on
///   `'unsafe-eval'` instead - both are 2022-2023 engines, older than the
///   WebCrypto/WebAuthn floor the app has anyway).
/// * `style-src 'self' 'unsafe-inline'` - the HTML carries static `style=`
///   attributes; JS writes element styles through the CSSOM, which CSP does
///   not gate.
/// * `img-src`/`media-src`/`frame-src` need `blob:` for the decrypt-and-blob
///   preview flow and `https:` so Markdown previews may reference external
///   images (the renderer already restricts URLs to `http(s)`, `/`, `#`).
/// * `frame-ancestors 'none'` - nothing may embed the app itself (the
///   sandboxed *preview* frames embed the other direction and keep the
///   route's own `sandbox` CSP; this layer never overwrites a header a route
///   set itself).
/// * `connect-src 'self'` - an injected script, however it got there, cannot
///   call home.
const CSP: HeaderValue = HeaderValue::from_static(concat!(
    "default-src 'self'; ",
    "script-src 'self' 'wasm-unsafe-eval'; ",
    "style-src 'self' 'unsafe-inline'; ",
    "img-src 'self' data: blob: https:; ",
    "media-src 'self' blob:; ",
    "frame-src 'self' blob:; ",
    "connect-src 'self'; ",
    "frame-ancestors 'none'; ",
    "base-uri 'self'; ",
    "form-action 'self'; ",
    "object-src 'none'"
));

/// Attach the baseline security headers to every response (Audit.md F2).
///
/// Each header is only added when the route has not set one itself: the
/// preview route answers with `Content-Security-Policy: sandbox` on purpose
/// and must keep exactly that, and the download route already sends its own
/// `nosniff`. HSTS rides along when the deployment declares HTTPS via
/// `FXCLOUD_SECURE_COOKIE` (the same knob that sets the cookie's Secure
/// attribute), so plain-HTTP installs are not affected.
async fn security_headers(State(state): State<SharedState>, request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    {
        let h = response.headers_mut();
        h.entry(header::X_CONTENT_TYPE_OPTIONS)
            .or_insert(HeaderValue::from_static("nosniff"));
        // SAMEORIGIN, not DENY: the app embeds its own previews (PDF and HTML
        // render in an iframe pointing back at this origin).
        h.entry(header::X_FRAME_OPTIONS)
            .or_insert(HeaderValue::from_static("SAMEORIGIN"));
        h.entry(header::REFERRER_POLICY)
            .or_insert(HeaderValue::from_static("same-origin"));
        h.entry(header::CONTENT_SECURITY_POLICY).or_insert(CSP.clone());
        if state.config.secure_cookie {
            h.entry(header::STRICT_TRANSPORT_SECURITY)
                .or_insert(HeaderValue::from_static("max-age=15552000"));
        }
    }
    response
}

/// Build the complete application router.
pub fn build_router(state: SharedState) -> Router {
    // Uploads arrive as multipart; lift axum's 2 MB default body limit so large
    // files don't get truncated mid-stream (which surfaces as a confusing
    // multipart parse error). Configurable via FXCLOUD_MAX_UPLOAD_MB.
    let max_upload = state.config.max_upload_bytes;

    let api = Router::new()
        // Auth
        .route("/register", post(routes::auth::register))
        .route("/login", post(routes::auth::login))
        .route("/logout", post(routes::auth::logout))
        .route("/me", get(routes::auth::me))
        .route("/me", put(routes::auth::update_me))
        .route("/me/password", put(routes::auth::change_password))
        // Account discovery for the share dialog
        .route("/users", get(routes::auth::list_users))
        // Files
        .route("/files", get(routes::files::list))
        .route("/files/folder", post(routes::files::create_folder))
        .route("/files/file", post(routes::files::create_file))
        .route("/files/folder/ensure", post(routes::files::ensure_folder))
        .route("/files/upload", post(routes::files::upload))
        .route("/files/download", get(routes::files::download))
        .route("/files/preview", get(routes::files::preview))
        .route("/files/content", put(routes::files::save_content))
        .route("/files/rename", post(routes::files::rename))
        .route("/files/delete", post(routes::files::delete))
        .route("/files/move", post(routes::files::move_entry))
        .route("/files/copy", post(routes::files::copy_entry))
        // Batch operations over a multi-selection
        .route("/files/batch/delete", post(routes::files::batch_delete))
        .route("/files/batch/move", post(routes::files::batch_move))
        .route("/files/batch/copy", post(routes::files::batch_copy))
        // ZIP download of a selection (prepare, then fetch with the token)
        .route("/files/zip", post(routes::files::prepare_zip))
        .route("/files/zip", get(routes::files::zip_download))
        .route("/files/breadcrumb", get(routes::files::breadcrumb))
        .route("/files/info", get(routes::files::info))
        // Trash bin: listing, restore, permanent delete, empty
        .route("/files/trash", get(routes::files::trash_list))
        .route("/files/trash/restore", post(routes::files::trash_restore))
        .route("/files/trash/purge", post(routes::files::trash_purge))
        .route("/files/trash/empty", post(routes::files::trash_empty))
        // Store a key record without touching bytes (folders on first
        // encrypted write, re-binding after a move, share-time migration).
        .route("/files/key", put(routes::files::put_key));
    // Sharing
    let api = api
        .route("/shares", post(routes::shares::create))
        .route("/shares/batch", post(routes::shares::create_batch))
        .route("/shares/outgoing", get(routes::shares::outgoing))
        .route("/shares/incoming", get(routes::shares::incoming))
        .route(
            "/shares/{id}",
            axum::routing::delete(routes::shares::revoke),
        );

    // Client-side encryption key material (ENCRYPTION.md section 6).
    // `/keys/me` is static, so it wins over `/keys/{username}` on that one
    // path; every other username falls through to the parameterised route.
    let api = api
        .route("/keys/setup", post(routes::keys::setup))
        .route("/keys/me", get(routes::keys::get_me))
        .route("/keys/me", put(routes::keys::put_me))
        .route("/keys/{username}", get(routes::keys::get_public));

    // User administration. Every handler takes the `AdminUser` extractor, so
    // a signed-in account without the administrator flag is rejected with 403
    // before any of this logic runs.
    let api = api
        .route("/admin/users", get(routes::admin::list_users))
        .route("/admin/users/{id}", put(routes::admin::update_user))
        .route(
            "/admin/users/{id}/password",
            post(routes::admin::reset_password),
        );

    // Passkeys (WebAuthn): ceremony endpoints for adding a device and for
    // signing in, plus the device list the settings dialog manages. The
    // register pair and `/me/passkeys` take the `AuthUser` extractor; the
    // login pair is deliberately public, like `/login`.
    let api = api
        .route(
            "/passkeys/register/start",
            post(routes::passkeys::register_start),
        )
        .route(
            "/passkeys/register/finish",
            post(routes::passkeys::register_finish),
        )
        .route("/passkeys/login/start", post(routes::passkeys::login_start))
        .route(
            "/passkeys/login/finish",
            post(routes::passkeys::login_finish),
        )
        .route("/me/passkeys", get(routes::passkeys::list))
        .route(
            "/me/passkeys/{id}",
            axum::routing::patch(routes::passkeys::rename),
        )
        .route(
            "/me/passkeys/{id}",
            axum::routing::delete(routes::passkeys::remove),
        );

    Router::new()
        // UI pages & embedded assets
        .route("/", get(ui::index))
        .route("/login", get(ui::login_page))
        .route("/assets/{*path}", get(ui::asset))
        // WebDAV endpoint (all methods; dispatched by HTTP verb inside)
        .route("/dav", any(crate::webdav::dispatch))
        .route("/dav/", any(crate::webdav::dispatch))
        .route("/dav/{*path}", any(crate::webdav::dispatch))
        .nest("/api", api)
        .layer(DefaultBodyLimit::max(max_upload))
        .layer(CompressionLayer::new())
        // Baseline security headers on every response, outermost so nothing
        // downstream can drop them (Audit.md F2).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .layer(TraceLayer::new_for_http().on_failure(
            |failure: ServerErrorsFailureClass, latency: Duration, _span: &tracing::Span| {
                // A full storage quota is a client-side condition — the
                // uploader simply ran out of room — so its 507 is reported at
                // warn instead of error; a journal full of rejections stays
                // readable. Genuine server faults (including the bare 500s
                // from webdav.rs::internal(), which log nothing of their own)
                // keep the default error level.
                let quota_rejected = matches!(
                    &failure,
                    ServerErrorsFailureClass::StatusCode(code)
                        if *code == StatusCode::INSUFFICIENT_STORAGE
                );
                if quota_rejected {
                    tracing::warn!(classification = %failure, ?latency, "response rejected");
                } else {
                    tracing::error!(classification = %failure, ?latency, "response failed");
                }
            },
        ))
        .with_state(state)
}
