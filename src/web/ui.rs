use axum::extract::{Path as AxumPath, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use rust_embed::RustEmbed;
use serde::Deserialize;

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
    let Some(token) =
        token_from_cookie_header(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()))
    else {
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
    serve_asset(
        "index.html",
        state.config.office_url.as_deref().unwrap_or(""),
    )
}

/// GET /login – the login/register page. Sends authenticated users home.
pub async fn login_page(
    State(state): State<SharedState>,
    headers: header::HeaderMap,
) -> Result<Response, AppError> {
    if is_logged_in(&state, &headers).await {
        return Ok(Redirect::to("/").into_response());
    }
    serve_asset("login.html", "")
}

/// Query of the help page: an optional language override.
#[derive(Deserialize)]
pub struct HelpQuery {
    pub lang: Option<String>,
}

/// The language cookie the UI writes on every apply (`i18n.js`), so the
/// server can serve the guide in the language the reader is already
/// using without any script on the page itself.
fn lang_cookie(headers: &header::HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        pair.trim()
            .strip_prefix("fxcloud_lang=")
            .map(|v| v.to_string())
            .filter(|v| matches!(v.as_str(), "en" | "de" | "tlh"))
    })
}

/// GET /help - the user guide as a static page, in the reader's language.
///
/// `?lang=` wins and is remembered in the same cookie the UI writes;
/// without either the English source serves (the guide's default and the
/// UI's). Deliberately no login gate: the guide is documentation, and a
/// reader who cannot get into the app is exactly who needs
/// troubleshooting.
pub async fn help_page(
    headers: header::HeaderMap,
    Query(params): Query<HelpQuery>,
) -> Result<Response, AppError> {
    let chosen = params
        .lang
        .as_deref()
        .filter(|l| matches!(*l, "en" | "de" | "tlh"))
        .map(|l| l.to_string());
    let lang = chosen
        .clone()
        .or_else(|| lang_cookie(&headers))
        .unwrap_or_else(|| "en".to_string());
    let mut response = serve_asset(&format!("assets/help-{lang}.html"), "")?;
    if let Some(wanted) = chosen {
        // Remember the choice the way the UI remembers its switcher.
        let cookie = format!("fxcloud_lang={wanted}; Path=/; Max-Age=31536000; SameSite=Lax");
        if let Ok(value) = cookie.parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    Ok(response)
}

/// GET /assets/{*path} – serve a static asset with sensible caching.
pub async fn asset(AxumPath(path): AxumPath<String>) -> Result<Response, AppError> {
    serve_asset(&format!("assets/{path}"), "")
}

/// GET /sw.js – the service worker (PWA install). Must live at the root so
/// its default scope is the whole origin, and mime_guess answers
/// `text/javascript`, which browsers require to accept a worker at all.
pub async fn service_worker() -> Result<Response, AppError> {
    serve_asset("sw.js", "")
}

/// GET /manifest.webmanifest – the PWA manifest (installability: name,
/// icons, start_url, display). mime_guess maps `.webmanifest` to
/// `application/manifest+json`, the type install prompts expect.
pub async fn manifest() -> Result<Response, AppError> {
    serve_asset("manifest.webmanifest", "")
}

/// Serve an embedded asset, filling the server-side template slots.
///
/// `office` is the engine base URL when office editing is configured and
/// the empty string otherwise: `index.html` parks it in a `data-office`
/// attribute, so the UI knows whether to offer the office editor at all
/// without an extra round trip (concepts/office.md section 5 - with the
/// feature off the attribute stays empty and nothing in the frontend
/// changes, decision 3).
fn serve_asset(path: &str, office: &str) -> Result<Response, AppError> {
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
        // Server-side template slots: the version badge next to the logo is
        // filled in from Cargo.toml, so display and release tag stay in step.
        let html = String::from_utf8_lossy(&data)
            .replace("{{version}}", VERSION)
            .replace("{{office}}", office);
        data = html.into_bytes();
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
