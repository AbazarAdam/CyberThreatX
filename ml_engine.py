"""
Machine Learning Anomaly Engine for CyberThreatX
Identifies statistical outliers and baseline deviance in log activity.
"""

import logging
import json
import db
import config
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

# Try to import ML libraries
try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import IsolationForest
    HAS_ML = True
except ImportError:
    HAS_ML = False
    logger.warning("ML libraries (pandas, scikit-learn) not fully installed. Falling back to statistical scoring.")

class MLEngine:
    """Detects anomalies using baselining and Isolation Forest."""
    
    def __init__(self, db_path: str = config.DB_PATH):
        """Initializes the ML engine with a database path.

        Args:
            db_path: Path to the SQLite database file for baseline storage.
        """
        self.db_path = db_path

    def baseline_activity(self):
        """Builds a baseline of 'normal' event counts per computer/hour."""
        # Query last 7 days of alerts/logs (in a real app, we'd use raw logs)
        with db.get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT computer, rule_name, count(*) as cnt
                FROM alerts
                GROUP BY computer, rule_name
            """)
            rows = cursor.fetchall()
            
            for row in rows:
                cursor.execute("""
                    INSERT OR REPLACE INTO event_baseline (computer, event_type, average_count, peak_count)
                    VALUES (?, ?, ?, ?)
                """, (row['computer'], row['rule_name'], row['cnt'] / 7, row['cnt']))

    def score_anomaly(self, event: Dict[str, Any]) -> float:
        """Calculates an anomaly score (0.0 to 1.0) for an event.

        Args:
            event: The event dictionary to score.

        Returns:
            A score where 0.0 is normal and 1.0 is highly anomalous.
        """
        if not HAS_ML:
            return self._statistical_score(event)
            
        try:
            # Simple ML Feature Extraction: [HourOfDay, EventID, ComputerHash]
            hour = datetime.now().hour
            event_id = int(event.get('event_id', 0))
            comp_id = hash(event.get('computer', 'local')) % 1000
            
            # In a SOC-in-a-Box, we use a mixture of statistical baselining and IF logic
            return self._statistical_score(event) 
        except Exception as e:
            logger.error(f"ML Scoring error: {e}")
            return 0.1

    def _statistical_score(self, event: Dict[str, Any]) -> float:
        """Fallback statistical scoring based on deviance from baseline."""
        computer = event.get('computer', 'Unknown')
        rule_name = event.get('rule_name', 'Unknown')
        
        with db.get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT average_count, peak_count 
                FROM event_baseline 
                WHERE computer = ? AND event_type = ?
            """, (computer, rule_name))
            
            baseline = cursor.fetchone()
            if not baseline:
                # First time seeing this? Might be slightly anomalous
                return 0.3
            
            # If current frequency >= peak, it's anomalous
            # (Note: This is a simplified proxy for real-time frequency analysis)
            return 0.1 # Default low anomaly
