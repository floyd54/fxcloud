use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::files::FileService;

/// Shared application state available to every handler.
pub struct AppState {
    pub db: Db,
    pub files: FileService,
    pub config: Config,
}

impl AppState {
    pub fn new(db: Db, config: Config) -> Self {
        let files = FileService::new(db.clone(), &config);
        Self { db, files, config }
    }
}

pub type SharedState = Arc<AppState>;
