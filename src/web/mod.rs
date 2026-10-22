pub mod routes;
pub mod state;
pub mod ui;

use axum::extract::DefaultBodyLimit;
use axum::routing::{any, get, post};
use axum::Router;
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
        // Files
        .route("/files", get(routes::files::list))
        .route("/files/folder", post(routes::files::create_folder))
        .route("/files/upload", post(routes::files::upload))
        .route("/files/download", get(routes::files::download))
        .route("/files/rename", post(routes::files::rename))
        .route("/files/delete", post(routes::files::delete))
        .route("/files/move", post(routes::files::move_entry))
        .route("/files/copy", post(routes::files::copy_entry))
        .route("/files/breadcrumb", get(routes::files::breadcrumb))
        .route("/files/info", get(routes::files::info));
    // Sharing
    let api = api
        .route("/shares", post(routes::shares::create))
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
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
