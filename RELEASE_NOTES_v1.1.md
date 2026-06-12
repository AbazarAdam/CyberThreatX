# Release Notes - CyberThreatX v1.1 (Stable Release Foundation)

**CyberThreatX v1.1** is a stabilization and optimization release focused on database synchronization, UI visual excellence, multi-threading stability, and release hardening.

---

## 🌟 Key Highlights

1. **Robust Concurrency**: SQLite transactions are hardened using Write-Ahead Logging (WAL) and automatic transaction retries with exponential backoff on table lock events (`@_retry_on_locked()`).
2. **Unified Data Directory**: All ingest routines, watchers, backend detectors, and dashboard servers reference the unified, environment-aware configuration `config.DB_PATH` by default, eliminating path misalignment risks.
3. **Legibility & Contrast Hardening**: Consolidates login validation blocks and restores full readable contrast to dashboard widgets, tables, and sidebar transitions.

---

## 💻 System & Installation Requirements

- **Operating System**: Windows / Linux / macOS
- **Python Version**: Python 3.8 or higher
- **Core Dependencies**:
  - `Flask` (Web dashboard, authentication, session state)
  - `watchdog` (Real-time log ingestion)
  - `PyYAML` (Sigma rules parsing)
  - `pysigma` (Sigma rule evaluation framework)

### Setup & Installation:

1. **Activate Virtual Environment**:
   ```powershell
   # Windows PowerShell
   .\.venv\Scripts\Activate.ps1
   ```
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Initialize Environment Settings**:
   ```powershell
   copy config.example.py config.py
   ```

---

## 🚀 Launch Sequence

### 1. Initialize and Run the Web Dashboard
```bash
python dashboard.py
```
* Dashboard will be accessible at: `http://localhost:5000`
* Default Admin Credentials: `admin` / `changeme`

### 2. Start the Real-time Log Watcher
```bash
python watcher.py
```
* Watches `monitored_logs` by default.
* Automatically ingests new EVTX, JSON, and CSV files, runs Sigma detections, baseline anomaly scoring, and saves matches into the shared database file.

---

## 🔍 Verification Checklist

Ensure the following verification steps are performed post-deployment:

### 1. Run the Automated Test Suite
Verify that event parser normalizations and Sigma rule compilation compile successfully:
```bash
python verify_fix.py
```

### 2. Verify Authentication Card Failures
Access the dashboard login page, type in invalid credentials (e.g. `bad_user`/`bad_password`), and verify that a warning alert banner immediately renders above the login inputs with clear instructions.

### 3. Verify Timestamp Legibility
Trigger a test alert and browse to `/alerts`. Ensure the incident table displays the event timestamps with a readable, high-contrast text color against the dark row styling.

### 4. Verify Sidebar Collapse Transition
Click the collapse list toggle in the top navbar. Ensure that side margins transition seamlessly and the sidebar text is hidden immediately without layout reflow issues.
