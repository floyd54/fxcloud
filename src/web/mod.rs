pub mod routes;
pub mod state;
pub mod ui;

use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::routing::{any, get, post};
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
        // Account discovery for the share dialog
        .route("/users", get(routes::auth::list_users))
        // Files
        .route("/files", get(routes::files::list))
        .route("/files/folder", post(routes::files::create_folder))
        .route("/files/folder/ensure", post(routes::files::ensure_folder))
        .route("/files/upload", post(routes::files::upload))
        .route("/files/download", get(routes::files::download))
        .route("/files/preview", get(routes::files::preview))
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
        .route("/files/info", get(routes::files::info));
    // Sharing
    let api = api
        .route("/shares", post(routes::shares::create))
        .route("/shares/batch", post(routes::shares::create_batch))
        .route("/shares/outgoing", get(routes::shares::outgoing))
        .route("/shares/incoming", get(routes::shares::incoming))
        .route("/shares/{id}", axum::routing::delete(routes::shares::revoke));

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
