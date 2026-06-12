"""
Configuration Template for CyberThreatX
Copy this file to config.py and update your settings.
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# App metadata
APP_NAME = "CyberThreatX"
APP_VERSION = "v1.1"
APP_TITLE = f"{APP_NAME} {APP_VERSION}"

# Runtime settings
DEBUG = os.getenv('CYBERTHREATX_DEBUG', 'false').lower() == 'true'
DASHBOARD_HOST = os.getenv('CYBERTHREATX_HOST', '0.0.0.0')
DASHBOARD_PORT = int(os.getenv('CYBERTHREATX_PORT', '5000'))

# Logging
LOG_LEVEL = os.getenv('CYBERTHREATX_LOG_LEVEL', 'INFO').upper()
LOG_FORMAT = os.getenv(
	'CYBERTHREATX_LOG_FORMAT',
	'%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOG_DATEFMT = os.getenv('CYBERTHREATX_LOG_DATEFMT', '%Y-%m-%d %H:%M:%S')

# Database configuration
# Path to the SQLite database file
DB_PATH = os.getenv('CYBERTHREATX_DB', str(BASE_DIR / 'cyberthreatx.db'))

# Security configuration
# Secret key for Flask sessions
SECRET_KEY = os.getenv('CYBERTHREATX_SECRET', 'your-secret-key-here')

# Ingestion configuration
# Directory to watch for new EVTX/JSON logs
MONITORED_LOGS_DIR = os.getenv('CYBERTHREATX_LOGS', str(BASE_DIR / 'monitored_logs'))
SIGMA_RULES_DIR = str(BASE_DIR / 'sigma_rules')
CORRELATION_RULES_DIR = str(BASE_DIR / 'correlation_rules')

# Syslog configuration
SYSLOG_ENABLED = os.getenv('SYSLOG_ENABLED', 'true').lower() == 'true'
SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', 514))
SYSLOG_HOST = os.getenv('SYSLOG_HOST', '0.0.0.0')

# Threat Intelligence configuration
# Add your API keys here
OTX_API_KEY = os.getenv('OTX_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
INTEL_CACHE_EXPIRY_DAYS = 7

# Correlation configuration
CORRELATION_ENABLED = True
DEFAULT_TIME_WINDOW = 300  # 5 minutes
DEDUPLICATION_COOLDOWN = 3600  # 1 hour

# Machine Learning configuration
ML_SCORING_ENABLED = True
BASELINE_UPDATE_INTERVAL_HOURS = 1

# Authentication configuration
ADMIN_DEFAULT_USER = "admin"
ADMIN_DEFAULT_PASS = "changeme"

# Feature Flags
ENABLE_THREAT_INTEL = bool(OTX_API_KEY or VIRUSTOTAL_API_KEY)
ENABLE_ML_ANOMALY = True
