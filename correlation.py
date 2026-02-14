"""
Alert Correlation Module for CyberThreatX
Groups similar alerts into "Correlations" to reduce noise and identify multi-stage attacks.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import db
import config

logger = logging.getLogger(__name__)

class CorrelationEngine:
    """Handles alert correlation and deduplication."""
    
    def __init__(self, db_path: str = config.DB_PATH):
        self.db_path = db_path

    def run_correlations(self):
        """Executes a standard correlation pass on recent un-correlated alerts."""
        # 1. Brute Force Detection (Threshold based)
        self.detect_brute_force()
        
        # 2. Multi-stage Attack (Sequence based)
        # self.detect_lateral_movement()

    def detect_brute_force(self, window_minutes: int = 10, threshold: int = 5):
        """Detects potential brute force attacks by grouping failures by computer.

        Args:
            window_minutes: The lookback window in minutes.
            threshold: Number of alerts required to trigger a correlation.
        """
        start_time = (datetime.now() - timedelta(minutes=window_minutes)).isoformat()
        
        # Query for recent 'new' alerts that look like failures
        # In a real app, we'd use rule IDs or specific tags
        with db.get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, rule_name, computer, raw_event 
                FROM alerts 
                WHERE created_at > ? 
                AND (rule_name LIKE '%Failure%' OR rule_name LIKE '%Brute%')
                AND status = 'new'
            """, (start_time,))
            
            alerts = cursor.fetchall()
            
            # Group by Computer
            groups = {}
            for alert in alerts:
                comp = alert['computer']
                if comp not in groups:
                    groups[comp] = []
                groups[comp].append(alert)
                
            for comp, comp_alerts in groups.items():
                if len(comp_alerts) >= threshold:
                    # Create a correlation
                    alert_ids = [a['id'] for a in comp_alerts]
                    self.create_correlation(
                        name="Potential Brute Force Attack",
                        description=f"Detected {len(comp_alerts)} failed login attempts on {comp} within {window_minutes} minutes.",
                        severity="high",
                        alert_ids=alert_ids
                    )

    def create_correlation(self, name: str, description: str, severity: str, alert_ids: List[int]):
        """Stores a new correlation in the database.

        Args:
            name: The title of the correlation incident.
            description: Detailed summary of why the alerts were grouped.
            severity: Overall severity level.
            alert_ids: List of alert IDs contributing to this correlation.
        """
        now = datetime.now().isoformat()
        correlation = {
            'correlation_name': name,
            'description': description,
            'severity': severity,
            'start_time': min([now]), # Placeholder for actual event logic
            'end_time': now,
            'group_key': f"BF_{alert_ids[0]}", 
            'contributing_alert_ids': json.dumps(alert_ids),
            'status': 'new'
        }
        
        db.insert_correlation_alert(correlation, self.db_path)
            
        logger.info(f"[!] Created Correlation: {name} ({len(alert_ids)} alerts)")

def run_correlation_cycle(db_path: str = config.DB_PATH):
    """Background entry point for correlation."""
    engine = CorrelationEngine(db_path)
    try:
        engine.run_correlations()
    except Exception as e:
        logger.error(f"Correlation error: {str(e)}")
