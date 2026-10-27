pub mod routes;
pub mod state;
pub mod ui;

use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::routing::{any, delete, get, post, put};
use axum::Router;
use tower_http::classify::ServerErrorsFailureClass;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;

use self::state::SharedState;

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
        // Optional sign-in passphrase (README, ENCRYPTION.md 5.7 addendum)
        .route("/me/passphrase", put(routes::auth::set_passphrase))
        .route("/me/passphrase", delete(routes::auth::remove_passphrase))
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
