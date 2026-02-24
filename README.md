# CyberThreatX (Version 4.0)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![SOC-in-a-Box](https://img.shields.io/badge/Capability-SOC--in--a--Box-red.svg)]()

**CyberThreatX** is a modern, lightweight SOC-in-a-Box solution designed for real-time threat detection, log ingestion, and alert management. It integrates Sigma rules, machine learning anomaly scoring, and threat intelligence to provide a comprehensive security monitoring platform.

---

## 🚀 Key Features

- 🔍 **Real-time Monitoring**: Watchdog-based file monitoring for EVTX, JSON, and CSV logs.
- 📜 **Sigma Integration**: Native support for Sigma rules with a custom Python-based backend.
- 🧠 **ML Anomaly Detection**: Statistical baselining and Isolation Forest (optional) for behavior analysis.
- 🌐 **Web Dashboard**: Modern Flask interface with alert triage, comments, and correlation views.
- 🔗 **Alert Correlation**: Automated grouping of related alerts (e.g., Brute Force detection).
- 🧬 **Threat Intel**: Automated enrichment with AlienVault OTX and VirusTotal.
- 🔐 **RBAC**: Role-based access control for Analysts and Admins.
- 📊 **Export Capability**: One-click Export to CSV for external reporting.
- 🐳 **Docker Ready**: Fully containerized for easy deployment.

---

## 🏗️ Architecture

```mermaid
graph TD
    subgraph "Ingestion Layer"
        W[File Watcher] --> |New Logs| P[Log Ingestor]
        S[Syslog Server] --> |Streams| P
    end

    subgraph "Detection Engine"
        P --> |Normalized Events| D[Detection Engine]
        D --> |Evaluate| SIG[Sigma Rules]
        D --> |Score| ML[ML Engine]
    end

    subgraph "Persistence & Service"
        D --> |Alerts| DB[(SQLite DB)]
        TI[Threat Intel] --> |Enrich| DB
        C[Correlation] --> |Group| DB
    end

    subgraph "Interface"
        DB --> |API/Data| UI[Flask Dashboard]
        UI --> |Triage| DB
    end
```

---

## 🛠️ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AbazarAdam/CyberThreatX.git
   cd CyberThreatX
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize Configuration:**
   ```bash
   cp config.example.py config.py
   # Edit config.py with your API keys and paths (if needed)
   ```

---

## 🖥️ Usage

### 🚀 Unified Launch (Recommended)
The easiest way to start both the dashboard and the log watcher is using the unified script:
```bash
python run_all.py
```
This will launch the dashboard at [http://localhost:5000](http://localhost:5000) and start monitoring the `monitored_logs` directory.

### Manual Launch
If you prefer to run components separately:

1. **Start the Dashboard**: `python dashboard.py`
2. **Start the Log Watcher**: `python watcher.py --watch-dir monitored_logs`

Access at [http://localhost:5000](http://localhost:5000). Default credentials: `admin` / `changeme`.

### ⚡ Manual Ingestion
```bash
python detect.py --file samples/security.evtx --db cyberthreatx.db
```

---

## 📂 Project Structure

- `dashboard.py`: Main Flask web interface.
- `detect.py`: Primary detection engine logic.
- `watcher.py`: Real-time file system monitoring.
- `log_ingest.py`: Log normalization and parsing.
- `sigma_backend.py`: Sigma to Python translation logic.
- `ml_engine.py`: Anomaly scoring and baselining.
- `db.py`: Database schema and operations.
- `config.py`: Centralized configuration.

---

## 📖 Documentation

For a detailed breakdown of the project architecture, challenges, and implementation details, see the [FINAL_REPORT.md](CYBERTHREATX_FINAL_REPORT.md).

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## 👤 Author

**Abazar Adam**
- GitHub: [@AbazarAdam](https://github.com/AbazarAdam)
