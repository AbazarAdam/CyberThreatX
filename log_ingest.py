"""
Unified Log Ingestion Module for CyberThreatX
Parses varied log formats (JSON, CSV, Syslog) into a common dictionary format.
"""

import json
import csv
import socket
import threading
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class LogIngestor:
    """Handles ingestion of different log formats."""
    
    @staticmethod
    def parse_json(file_path: str) -> List[Dict[str, Any]]:
        """Parses a JSON-lines file into a list of event dictionaries.

        Args:
            file_path: Path to the JSON file.

        Returns:
            A list of dictionaries representing the parsed events.
        """
        events = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        events.append(json.loads(line))
        except Exception as e:
            logger.error(f"Error parsing JSON file {file_path}: {e}")
        return events

    @staticmethod
    def parse_csv(file_path: str) -> List[Dict[str, Any]]:
        """Parses a CSV file with headers into a list of event dictionaries.

        Args:
            file_path: Path to the CSV file.

        Returns:
            A list of dictionaries representing the parsed events.
        """
        events = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    events.append(dict(row))
        except Exception as e:
            logger.error(f"Error parsing CSV file {file_path}: {e}")
        return events

    @staticmethod
    def normalize_event(raw_event: Dict[str, Any], source_type: str) -> Dict[str, Any]:
        """Normalizes an event from any source into a common CyberThreatX schema.

        Args:
            raw_event: The raw event data dictionary.
            source_type: The source type string (e.g., 'evtx', 'json', 'syslog').

        Returns:
            A normalized event dictionary.
        """
        # Default mapping logic (can be extended via config)
        event_id_raw = raw_event.get('event_id') or raw_event.get('Id') or raw_event.get('EventID')
        
        # Handle dict case for EventID (common in some JSON exports)
        if isinstance(event_id_raw, dict):
            event_id = event_id_raw.get('#text')
        else:
            event_id = event_id_raw
            
        normalized = {
            'timestamp': raw_event.get('timestamp') or raw_event.get('TimeCreated') or datetime.now().isoformat(),
            'event_id': event_id if event_id is not None else "N/A",
            'computer': raw_event.get('computer') or raw_event.get('Computer') or 'Unknown',
            'provider': raw_event.get('provider') or raw_event.get('ProviderName') or source_type,
            'event_data': raw_event.get('event_data') or raw_event,
            'raw': raw_event
        }
        return normalized

def start_syslog_server(host: str, port: int, callback):
    """Starts a UDP syslog server in a background thread.

    Args:
        host: Hostname or IP to bind to.
        port: Port to listen on.
        callback: Function to call for each received event.

    Returns:
        The threading.Thread object running the server.
    """
    def listen():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        logger.info(f"[*] Syslog server listening on {host}:{port}")
        
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                msg = data.decode('utf-8')
                # Simple syslog parser (RFC3164/5424)
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'source_ip': addr[0],
                    'message': msg,
                    'provider': 'syslog'
                }
                callback(event)
            except Exception as e:
                logger.error(f"Error processing syslog from {addr}: {e}")

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    return thread
