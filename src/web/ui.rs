use axum::extract::{Path as AxumPath, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use rust_embed::RustEmbed;

use crate::auth::token_from_cookie_header;
use crate::error::AppError;
use crate::web::state::SharedState;

/// Frontend assets compiled into the binary at build time.
#[derive(RustEmbed)]
#[folder = "frontend/"]
struct Assets;

async fn is_logged_in(state: &SharedState, headers: &header::HeaderMap) -> bool {
    let Some(token) = token_from_cookie_header(
        headers.get(header::COOKIE).and_then(|v| v.to_str().ok()),
    ) else {
        return false;
    };
    matches!(state.db.session_user_id(token).await, Ok(Some(_)))
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
        // Hashed-ish long cache for CSS/JS; adjust when adding asset fingerprinting.
        "public, max-age=3600"
    };

    Ok((
        [
            (header::CONTENT_TYPE, mime),
            (header::CACHE_CONTROL, cache.to_string()),
        ],
        file.data.into_owned(),
    )
        .into_response())
}
