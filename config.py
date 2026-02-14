"""
Central Configuration for CyberThreatX (Version 4)
Provides a unified way to manage settings and environment variables.
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Database configuration
DB_PATH = os.getenv('CYBERTHREATX_DB', str(BASE_DIR / 'cyberthreatx.db'))

# Security configuration
SECRET_KEY = os.getenv('CYBERTHREATX_SECRET', 'cyberthreatx-default-secret-key-change-it')

# Ingestion configuration
MONITORED_LOGS_DIR = os.getenv('CYBERTHREATX_LOGS', str(BASE_DIR / 'monitored_logs'))
SIGMA_RULES_DIR = str(BASE_DIR / 'sigma_rules')
CORRELATION_RULES_DIR = str(BASE_DIR / 'correlation_rules')

# Syslog configuration
SYSLOG_ENABLED = os.getenv('SYSLOG_ENABLED', 'true').lower() == 'true'
SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', 514))
SYSLOG_HOST = os.getenv('SYSLOG_HOST', '0.0.0.0')

# Threat Intelligence configuration
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
ADMIN_DEFAULT_PASS = "changeme"  # Should be changed on first login

# Feature Flags
ENABLE_THREAT_INTEL = bool(OTX_API_KEY or VIRUSTOTAL_API_KEY)
ENABLE_ML_ANOMALY = True
