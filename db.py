"""
Database Module for CyberThreatX
Handles all SQLite operations for storing and retrieving threat alerts.
"""
import sqlite3
import json
import logging
import config
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from contextlib import contextmanager


# Database file path
DB_FILE = "cyberthreatx.db"

# Password hashing
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)


@contextmanager
def get_connection(db_path: str = config.DB_PATH):
    """Provides a managed database connection with WAL mode and row factory.

    Args:
        db_path: Path to the SQLite database file.

    Yields:
        A sqlite3.Connection object.
    """
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row  # Enable column access by name
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_db(db_path: str = config.DB_PATH) -> None:
    """Initializes the database schema and performs necessary migrations.

    Args:
        db_path: Path to the database file.
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # 1. Alerts Table (Updated for V4)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                score INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                computer TEXT NOT NULL,
                description TEXT NOT NULL,
                mitre_technique TEXT DEFAULT '',
                raw_event TEXT NOT NULL,
                status TEXT DEFAULT 'new',
                assigned_to INTEGER,
                threat_intel TEXT,
                anomaly_score REAL DEFAULT 0.0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Migration: Add status, assigned_to, and threat_intel columns if they don't exist
        cursor.execute("PRAGMA table_info(alerts)")
        columns = [row['name'] for row in cursor.fetchall()]
        
        if 'status' not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'new'")
        if 'assigned_to' not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN assigned_to INTEGER")
        if 'threat_intel' not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN threat_intel TEXT")
        if 'anomaly_score' not in columns:
            cursor.execute("ALTER TABLE alerts ADD COLUMN anomaly_score REAL DEFAULT 0.0")
            
        # 2. Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 3. Correlation Alerts Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS correlation_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_name TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                group_key TEXT,
                contributing_alert_ids TEXT, -- JSON list
                status TEXT DEFAULT 'new',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 4. Alert Comments Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alert_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                user_id INTEGER,
                comment TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (alert_id) REFERENCES alerts(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # 5. Audit Log Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id INTEGER,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # 6. Threat Intel Cache Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                source TEXT NOT NULL,
                result TEXT, -- JSON string
                last_queried TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ioc_type, ioc_value, source)
            )
        """)
        
        # 7. Event Baseline Table (for ML Scoring)
        cursor.execute("DROP TABLE IF EXISTS event_baseline")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_baseline (
                computer TEXT NOT NULL,
                event_type TEXT NOT NULL,
                average_count REAL,
                peak_count INTEGER,
                last_updated TEXT DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (computer, event_type)
            )
        """)
        
        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_assigned ON alerts(assigned_to)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_corr_status ON correlation_alerts(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_intel_ioc ON threat_intel_cache(ioc_value)")
        
        logger.info(f"[✓] Database initialized/upgraded: {db_path}")


def insert_alert(alert_dict: Dict[str, Any], db_path: str = config.DB_PATH) -> int:
    """Inserts a new alert into the database.

    Args:
        alert_dict: A dictionary containing the alert data.
        db_path: Output database file path.

    Returns:
        The ID of the inserted alert row.
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Convert raw_event to JSON string
        raw_event_json = json.dumps(alert_dict.get('raw_event', {}))
        
        # Get current timestamp
        created_at = datetime.utcnow().isoformat()
        
        cursor.execute("""
            INSERT INTO alerts (
                timestamp, rule_name, severity, score, event_id,
                computer, description, mitre_technique, raw_event,
                status, assigned_to, threat_intel, anomaly_score, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_dict.get('timestamp', ''),
            alert_dict.get('rule_name', ''),
            alert_dict.get('severity', ''),
            alert_dict.get('score', 0),
            alert_dict.get('event_id', 0),
            alert_dict.get('computer', ''),
            alert_dict.get('description', ''),
            alert_dict.get('mitre_technique', ''),
            raw_event_json,
            alert_dict.get('status', 'new'),
            alert_dict.get('assigned_to'),
            alert_dict.get('threat_intel'),
            alert_dict.get('anomaly_score', 0.0),
            created_at
        ))
        
        alert_id = cursor.lastrowid
        
        return alert_id


def get_alerts(
    filters: Optional[Dict[str, Any]] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: str = DB_FILE
) -> List[Dict[str, Any]]:
    """
    Retrieve alerts from the database with optional filtering.
    
    Args:
        filters: Dictionary with optional keys:
            - severity: Filter by severity level
            - rule_name: Filter by rule name
            - start_date: Filter by start date (ISO format)
            - end_date: Filter by end date (ISO format)
        limit: Maximum number of results
        offset: Offset for pagination
        db_path: Path to SQLite database file
        
    Returns:
        List of alert dictionaries
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Build query
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        
        if filters:
            if filters.get('severity'):
                query += " AND severity = ?"
                params.append(filters['severity'])
            
            if filters.get('rule_name'):
                query += " AND rule_name = ?"
                params.append(filters['rule_name'])
            
            if filters.get('start_date'):
                query += " AND timestamp >= ?"
                params.append(filters['start_date'])
            
            if filters.get('end_date'):
                query += " AND timestamp <= ?"
                params.append(filters['end_date'])
        
        # Order by most recent first
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # Convert to list of dicts
        alerts = []
        for row in rows:
            alert = dict(row)
            # Parse raw_event JSON
            alert['raw_event'] = json.loads(alert['raw_event'])
            alerts.append(alert)
        
        return alerts


def get_alert_by_id(alert_id: int, db_path: str = DB_FILE) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single alert by ID.
    
    Args:
        alert_id: Alert ID
        db_path: Path to SQLite database file
        
    Returns:
        Alert dictionary or None if not found
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        
        if row:
            alert = dict(row)
            alert['raw_event'] = json.loads(alert['raw_event'])
            return alert
        
        return None


def get_stats(db_path: str = DB_FILE) -> Dict[str, Any]:
    """
    Calculate statistics about alerts.
    
    Returns:
        Dictionary with statistics:
        - total_alerts: Total number of alerts
        - alerts_by_severity: Dict of severity -> count
        - top_rules: List of (rule_name, count) tuples
        - alerts_last_24h: Count of alerts in last 24 hours
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        # Total alerts
        cursor.execute("SELECT COUNT(*) as count FROM alerts")
        total_alerts = cursor.fetchone()['count']
        
        # Alerts by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count
            FROM alerts
            GROUP BY severity
        """)
        alerts_by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Top 5 rules
        cursor.execute("""
            SELECT rule_name, COUNT(*) as count
            FROM alerts
            GROUP BY rule_name
            ORDER BY count DESC
            LIMIT 5
        """)
        top_rules = [(row['rule_name'], row['count']) for row in cursor.fetchall()]
        
        # Alerts in last 24 hours
        twenty_four_hours_ago = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        cursor.execute("""
            SELECT COUNT(*) as count
            FROM alerts
            WHERE created_at >= ?
        """, (twenty_four_hours_ago,))
        alerts_last_24h = cursor.fetchone()['count']
        
        return {
            'total_alerts': total_alerts,
            'alerts_by_severity': alerts_by_severity,
            'top_rules': top_rules,
            'alerts_last_24h': alerts_last_24h
        }


def get_alert_count(filters: Optional[Dict[str, Any]] = None, db_path: str = DB_FILE) -> int:
    """
    Get total count of alerts matching filters (for pagination).
    
    Args:
        filters: Same filter dict as get_alerts()
        db_path: Path to SQLite database file
        
    Returns:
        Total count of matching alerts
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        
        query = "SELECT COUNT(*) as count FROM alerts WHERE 1=1"
        params = []
        
        if filters:
            if filters.get('severity'):
                query += " AND severity = ?"
                params.append(filters['severity'])
            
            if filters.get('rule_name'):
                query += " AND rule_name = ?"
                params.append(filters['rule_name'])
            
            if filters.get('start_date'):
                query += " AND timestamp >= ?"
                params.append(filters['start_date'])
            
            if filters.get('end_date'):
                query += " AND timestamp <= ?"
                params.append(filters['end_date'])
        
        cursor.execute(query, params)
        return cursor.fetchone()['count']


def get_unique_rules(db_path: str = DB_FILE) -> List[str]:
    """
    Get list of unique rule names in the database.
    
    Returns:
        List of rule names
    """
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT rule_name FROM alerts ORDER BY rule_name")
        return [row['rule_name'] for row in cursor.fetchall()]



# --- User Management ---

def create_user(username: str, password_raw: str, role: str = 'analyst', db_path: str = DB_FILE) -> int:
    """Create a new user with a hashed password."""
    password_hash = generate_password_hash(password_raw)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        return cursor.lastrowid

def get_user_by_username(username: str, db_path: str = DB_FILE) -> Optional[Dict[str, Any]]:
    """Get user details by username."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_id(user_id: int, db_path: str = DB_FILE) -> Optional[Dict[str, Any]]:
    """Get user details by ID."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def verify_user(username: str, password_raw: str, db_path: str = DB_FILE) -> Optional[Dict[str, Any]]:
    """Verify user credentials and return user dict if successful."""
    user = get_user_by_username(username, db_path)
    if user and check_password_hash(user['password_hash'], password_raw):
        return user
    return None

# --- Alert Triage ---

def update_alert_status(alert_id: int, status: str, user_id: int = None, db_path: str = DB_FILE) -> bool:
    """Update alert status and log action."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        log_action(user_id, 'update_status', 'alert', alert_id, f"Changed status to {status}", db_path)
        return True

def assign_alert(alert_id: int, user_id: int, assigner_id: int = None, db_path: str = DB_FILE) -> bool:
    """Assign alert to a user."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE alerts SET assigned_to = ? WHERE id = ?", (user_id, alert_id))
        log_action(assigner_id, 'assign_alert', 'alert', alert_id, f"Assigned to user {user_id}", db_path)
        return True

def add_alert_comment(alert_id: int, user_id: int, comment: str, db_path: str = DB_FILE) -> int:
    """Add a comment to an alert."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO alert_comments (alert_id, user_id, comment) VALUES (?, ?, ?)",
            (alert_id, user_id, comment)
        )
        comment_id = cursor.lastrowid
        log_action(user_id, 'add_comment', 'alert', alert_id, "Added comment", db_path)
        return comment_id

def get_alert_comments(alert_id: int, db_path: str = DB_FILE) -> List[Dict[str, Any]]:
    """Get all comments for an alert with usernames."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.*, u.username
            FROM alert_comments c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.alert_id = ?
            ORDER BY c.created_at ASC
        """, (alert_id,))
        return [dict(row) for row in cursor.fetchall()]

# --- Correlation Management ---

def get_correlations(db_path: str = DB_FILE, limit: int = 100, offset: int = 0, status: str = None) -> List[Dict[str, Any]]:
    """Return a list of correlation alerts, optionally filtered by status."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM correlation_alerts"
        params = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

def get_correlation_by_id(corr_id: int, db_path: str = DB_FILE) -> Optional[Dict[str, Any]]:
    """Retrieve a single correlation by ID."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM correlation_alerts WHERE id = ?", (corr_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def insert_correlation_alert(data: Dict[str, Any], db_path: str = DB_FILE) -> int:
    """Insert a new correlation alert."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO correlation_alerts 
            (correlation_name, description, severity, start_time, end_time, group_key, contributing_alert_ids, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data['correlation_name'],
            data['description'],
            data['severity'],
            data['start_time'],
            data['end_time'],
            data['group_key'],
            data.get('contributing_alert_ids', '[]'),
            data.get('status', 'new')
        ))
        return cursor.lastrowid

def update_correlation_status(corr_id: int, status: str, db_path: str = DB_FILE) -> bool:
    """Update correlation status."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE correlation_alerts SET status = ? WHERE id = ?", (status, corr_id))
        return True

# --- Audit & Logging ---

def log_action(user_id: int, action: str, target_type: str = None, target_id: int = None, details: str = None, db_path: str = DB_FILE):
    """Log system actions for auditing."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_log (user_id, action, target_type, target_id, details)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, action, target_type, target_id, details))

# --- ML Baseline (Partial) ---

def update_baseline(computer: str, event_id: int, hour: int, day: int, count: int, db_path: str = DB_FILE):
    """Update historical baseline for an event."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        # Simple moving average placeholder
        cursor.execute("""
            INSERT INTO event_baseline (computer, event_id, hour, day_of_week, avg_count, last_updated)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(computer, event_id, hour, day_of_week) DO UPDATE SET
                avg_count = (avg_count * 0.9) + (? * 0.1),
                last_updated = CURRENT_TIMESTAMP
        """, (computer, event_id, hour, day, count, count))
