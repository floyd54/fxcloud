-- Per-user UI theme, chosen in the user menu (settings). The web app reads it
-- from GET /api/me and applies it as data-theme on <html>; the server only
-- stores and validates it, never renders it.
ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'light';
