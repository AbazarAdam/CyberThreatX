# Changelog - CyberThreatX v1.1 (Stabilization Release)

All notable changes to the **CyberThreatX** project under the **v1.1** release foundation are documented below.

## [v1.1] - 2026-05-22

### Added
- Created `CHANGELOG_v1.1.md` to track architectural and design modifications systematically.
- Created `RELEASE_NOTES_v1.1.md` detailing fresh setup instructions, automated verification, and validation checklists.
- Integrated a new `.timestamp-contrast` helper in `static/css/style.css` matching GitHub-style dark aesthetics for enhanced data table scanning.

### Changed
- **Centralized Database Path Alignment**: Refactored the core database module `db.py` to point its default parameter path `DB_FILE` directly to the centralized, absolute environment-resolved configuration `config.DB_PATH` rather than hardcoding local relative strings.
- **Log Watcher Sync**: Aligned the default database argument in the watchdog runner `watcher.py` to inherit `config.DB_PATH` by default, ensuring all active files ingested real-time flow directly into the configured database file.
- **Improved Sidebar Collapse Aesthetics**: Added `overflow-x: hidden` to `#sidebar` in `static/css/style.css` to prevent ugly, flickering text-wrapping reflows during expand/collapse transition cycles. Added collapsed-width padding adjustments for list items in the sidebar.

### Fixed
- **Authentication Card Silent Failures**: Removed duplicate `get_flashed_messages()` evaluation inside `templates/login.html`. Consolidating this block ensures that login error details are consumed exactly once and render properly.
- **Legibility Contrast in Triage View**: Swapped the unreadable `text-black-force` class on the event timestamp column in `templates/alerts.html` with `timestamp-contrast`, restoring high-contrast legibility against dark `#161b22` alert cards.
- **Verified SQLite Concurrency**: Audited all database-writing commands (e.g. `insert_alert`, `add_notification`, `create_user`) to verify that the `@_retry_on_locked()` exponential backoff decorator is properly configured, guaranteeing multi-thread safe execution under continuous ingestion load.
