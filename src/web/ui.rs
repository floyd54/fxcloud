use axum::extract::{Path as AxumPath, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use rust_embed::RustEmbed;

use crate::auth::token_from_cookie_header;
use crate::error::AppError;
use crate::web::state::SharedState;

/// Release version shown in the UI, taken from `Cargo.toml` at build time so
/// the badge next to the logo always matches the binary (and the git tag).
const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// Frontend assets compiled into the binary at build time.
#[derive(RustEmbed)]
#[folder = "frontend/"]
struct Assets;

/// Whether the request carries a live session for an **active** account.
///
/// A deactivated user is treated as logged out so their browser lands on
/// `/login` instead of the app shell (whose API calls would all 401 anyway).
async fn is_logged_in(state: &SharedState, headers: &header::HeaderMap) -> bool {
    let Some(token) = token_from_cookie_header(
        headers.get(header::COOKIE).and_then(|v| v.to_str().ok()),
    ) else {
        return false;
    };
    let Ok(Some(user_id)) = state.db.session_user_id(token).await else {
        return false;
    };
    matches!(
        state.db.find_user_by_id(user_id).await,
        Ok(Some(user)) if user.is_active
    )
}

/// GET / – the file explorer app. Redirects to /login when unauthenticated.
pub async fn index(
    State(state): State<SharedState>,
    headers: header::HeaderMap,
) -> Result<Response, AppError> {
    if !is_logged_in(&state, &headers).await {
        return Ok(Redirect::to("/login").into_response());
    }
    serve_asset("index.html")
}

/// GET /login – the login/register page. Sends authenticated users home.
pub async fn login_page(
    State(state): State<SharedState>,
    headers: header::HeaderMap,
) -> Result<Response, AppError> {
    if is_logged_in(&state, &headers).await {
        return Ok(Redirect::to("/").into_response());
    }
    serve_asset("login.html")
}

/// GET /assets/{*path} – serve a static asset with sensible caching.
pub async fn asset(AxumPath(path): AxumPath<String>) -> Result<Response, AppError> {
    serve_asset(&format!("assets/{path}"))
}

fn serve_asset(path: &str) -> Result<Response, AppError> {
    let Some(file) = Assets::get(path) else {
        return Err(AppError::NotFound);
    };
    let mime = mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();

    let cache = if path == "index.html" || path == "login.html" {
        "no-cache"
    } else {
        // No fingerprinting yet, so never let browsers sit on stale JS/CSS:
        // `no-cache` forces a revalidation on every load (the assets are tiny).
        "no-cache"
    };

    let mut data = file.data.into_owned();
    if path.ends_with(".html") {
        // Server-side template slot: the version badge next to the logo is
        // filled in from Cargo.toml, so display and release tag stay in step.
        let html = String::from_utf8_lossy(&data).replace("{{version}}", VERSION);
        data = html.into_bytes().into();
    }

    Ok((
        [
            (header::CONTENT_TYPE, mime),
            (header::CACHE_CONTROL, cache.to_string()),
        ],
        data,
    )
        .into_response())
}
