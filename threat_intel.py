"""
Threat Intelligence Enrichment Module for CyberThreatX
Extracts IOCs from alerts and queries reputation feeds (OTX, VirusTotal).
"""

import re
import requests
import json
import logging
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
import db
import config

logger = logging.getLogger(__name__)

class ThreatIntelEngine:
    """Handles IOC extraction and enrichment."""
    
    # Simple regex for IOC extraction
    IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    DOMAIN_REGEX = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]\b'
    HASH_REGEX = r'\b[a-fA-F0-9]{32,64}\b' # MD5, SHA1, SHA256

    def __init__(self, db_path: str = config.DB_PATH):
        """Initializes the Threat Intel engine.

        Args:
            db_path: Path to the SQLite database.
        """
        self.db_path = db_path

    def extract_iocs(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Recursively search for IOCs in a dictionary."""
        iocs = {'ip': set(), 'domain': set(), 'hash': set()}
        
        data_str = json.dumps(data)
        
        # Find IPs
        ips = re.findall(self.IP_REGEX, data_str)
        for ip in ips:
            # Basic validation to skip common internal IPs if needed
            if not ip.startswith(('127.', '0.')):
                iocs['ip'].add(ip)
                
        # Find Domains
        domains = re.findall(self.DOMAIN_REGEX, data_str)
        for domain in domains:
            if '.' in domain and not domain.endswith(('.local', '.lan', '.internal')):
                iocs['domain'].add(domain)
                
        # Find Hashes
        hashes = re.findall(self.HASH_REGEX, data_str)
        for h in hashes:
            iocs['hash'].add(h)
            
        return {k: list(v) for k, v in iocs.items()}

    def query_otx(self, ioc_type: str, ioc_value: str) -> Optional[Dict[str, Any]]:
        """Queries AlienVault OTX for an IOC.

        Args:
            ioc_type: Type of IOC ('ip', 'domain', 'hash').
            ioc_value: The IOC value to query.

        Returns:
            The OTX response dictionary or None.
        """
        if not config.OTX_API_KEY:
            return None
            
        # OTX Type mapping
        otx_types = {'ip': 'IPv4', 'domain': 'domain', 'hash': 'file'}
        otx_type = otx_types.get(ioc_type)
        
        url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc_value}/general"
        headers = {'X-OTX-API-KEY': config.OTX_API_KEY}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logger.error(f"OTX query error for {ioc_value}: {e}")
        return None

    def enrich_alert(self, alert_id: int):
        """Performs background enrichment for a specific alert.

        Args:
            alert_id: The ID of the alert to enrich.
        """
        alert = db.get_alert_by_id(alert_id, self.db_path)
        if not alert:
            return

        iocs = self.extract_iocs(alert['raw_event'])
        enrichment_results = []
        
        for ioc_type, values in iocs.items():
            for val in values:
                # Check cache first
                # (Implementation of cache lookup goes here)
                
                result = self.query_otx(ioc_type, val)
                if result and result.get('pulse_info', {}).get('count', 0) > 0:
                    enrichment_results.append({
                        'type': ioc_type,
                        'value': val,
                        'source': 'OTX',
                        'pulses': result['pulse_info']['count']
                    })
                    
        if enrichment_results:
            # Update alert with summary
            with db.get_connection(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE alerts SET threat_intel = ? WHERE id = ?",
                    (json.dumps(enrichment_results), alert_id)
                )

def enrich_alert_background(alert_id: int, db_path: str = config.DB_PATH):
    """Entry point for background enrichment thread.

    Args:
        alert_id: The ID of the alert to enrich.
        db_path: Path to the SQLite database.
    """
    engine = ThreatIntelEngine(db_path)
    thread = threading.Thread(target=engine.enrich_alert, args=(alert_id,))
    thread.start()
    logger.info(f"[*] Started background enrichment for alert {alert_id}")
