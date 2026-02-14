"""
CyberThreatX - Threat Detection Engine (Version 3)
Main entry point for parsing EVTX files and detecting threats using Sigma rules.
"""

import argparse
import json
import sys
import logging
from pathlib import Path
from typing import Dict, Any, List, Tuple, Callable
from tqdm import tqdm

from evtx_parser import parse_evtx
import sigma_loader
import sigma_backend
from log_ingest import LogIngestor
import threat_intel
import ml_engine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def severity_to_score(severity: str) -> int:
    """Converts a severity level string to a numeric threat score.

    Args:
        severity: The severity level (low, medium, high, critical).

    Returns:
        The corresponding numeric score (0-10).
    """
    severity_map = {
        "low": 3,
        "medium": 6,
        "high": 9,
        "critical": 10
    }
    return severity_map.get(severity.lower(), 6)  # Default to medium


def calculate_score(matched_levels: List[str]) -> int:
    """Calculates an overall threat score based on multiple matched rules.

    Args:
        matched_levels: A list of severity level strings from matched rules.

    Returns:
        The final incident score capped at 10.
    """
    if not matched_levels:
        return 0
    
    # Get highest severity score
    max_severity_score = max(severity_to_score(level) for level in matched_levels)
    
    # Add bonus for multiple detections
    bonus = len(matched_levels) - 1
    
    return min(max_severity_score + bonus, 10)


def create_alert(event: Dict[str, Any], results: List[Dict[str, Any]], source_type: str = 'evtx') -> Dict[str, Any]:
    """Creates a normalized alert dictionary from a matched event.

    Args:
        event: The raw event data.
        results: A list of metadata dictionaries from matched Sigma rules.
        source_type: The type of log source.

    Returns:
        A dictionary containing the full alert information.
    """
    # Extract severity levels for scoring
    levels = [r['level'] for r in results]
    score = calculate_score(levels)
    
    # Determine primary rule (highest severity)
    level_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    primary_res = max(results, key=lambda r: level_rank.get(r['level'], 2))
    
    # Normalize event structure for standard alert storage
    norm = LogIngestor.normalize_event(event, source_type)
    
    # Calculate anomaly score
    ml = ml_engine.MLEngine()
    anomaly_score = ml.score_anomaly(event)
    
    # Build alert
    alert = {
        "timestamp": norm['timestamp'],
        "rule_name": primary_res['title'],
        "severity": primary_res['level'],
        "score": score,
        "anomaly_score": anomaly_score,
        "event_id": norm['event_id'],
        "computer": norm['computer'],
        "description": primary_res['description'],
        "mitre_technique": primary_res['mitre_techniques'][0] if primary_res['mitre_techniques'] else "",
        "matched_rules": [r['title'] for r in results],
        "raw_event": norm['raw']
    }
    
    return alert

# Cache for compiled rules to avoid redundant compilation
_COMPILED_RULES_CACHE = None

def run_detection_on_event(event: Dict[str, Any], db_path: str, rules_folder: str, source_type: str = 'syslog') -> Optional[Dict[str, Any]]:
    """Evaluates Sigma rules on a single normalized event using a cached backend.

    Args:
        event: The event dictionary to scan.
        db_path: Path to the SQLite database.
        rules_folder: Path to the folder containing Sigma rules.
        source_type: Log source type for normalization.

    Returns:
        The generated alert dictionary if a rule matched, else None.
    """
    global _COMPILED_RULES_CACHE
    
    if _COMPILED_RULES_CACHE is None:
        rule_paths = list(Path(rules_folder).rglob("*.yml")) + list(Path(rules_folder).rglob("*.yaml"))
        _COMPILED_RULES_CACHE = sigma_backend.compile_sigma_rules_from_files([str(p) for p in rule_paths])
    
    matched_results = []
    for rule_dict, matcher in _COMPILED_RULES_CACHE:
        if matcher(event):
            metadata = sigma_loader.get_rule_metadata_from_dict(rule_dict)
            matched_results.append(metadata)
            
    if matched_results:
        alert = create_alert(event, matched_results, source_type)
        import db
        db.init_db(db_path)
        alert_id = db.insert_alert(alert, db_path)
        
        # Trigger enrichment in background
        if alert_id:
            threat_intel.enrich_alert_background(alert_id, db_path)
            
        return alert
    return None


def process_evtx_file(
    evtx_file: str,
    db_path: str = None,
    json_output: str = None,
    rules_folder: str = "sigma_rules",
    show_progress: bool = True
) -> Dict[str, int]:
    """Processes an EVTX file and generates alerts using Sigma rules.

    Args:
        evtx_file: Path to the Windows Event Log file.
        db_path: Path to the SQLite database (optional).
        json_output: Path to save results as JSON (optional).
        rules_folder: Path to Sigma rules directory.
        show_progress: Whether to show a CLI progress bar.

    Returns:
        A dictionary with processing statistics.
    """
    evtx_path = Path(evtx_file)
    if not evtx_path.exists():
        error_msg = f"EVTX file not found: {evtx_file}"
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)
    
    sigma_rules = sigma_loader.load_sigma_rules(rules_folder)
    rule_paths = list(Path(rules_folder).rglob("*.yml")) + list(Path(rules_folder).rglob("*.yaml"))
    compiled_rules = sigma_backend.compile_sigma_rules_from_files([str(p) for p in rule_paths])

    use_database = db_path is not None
    if use_database:
        import db
        db.init_db(db_path)
    
    if show_progress:
        logger.info(f"[*] CyberThreatX - Threat Detection Engine v4.0")
        logger.info(f"[*] Processing: {evtx_file}")
    
    alerts_count = 0
    events_processed = 0
    
    try:
        if show_progress:
            pbar = tqdm(desc="Scanning events", unit=" events", colour="cyan")
        
        for event in parse_evtx(evtx_file):
            events_processed += 1
            if show_progress:
                pbar.update(1)
            
            matched_results = []
            for rule_dict, matcher in compiled_rules:
                if matcher(event):
                    metadata = sigma_loader.get_rule_metadata_from_dict(rule_dict)
                    matched_results.append(metadata)
            
            if matched_results:
                alert = create_alert(event, matched_results, 'evtx')
                if use_database:
                    import db
                    alert_id = db.insert_alert(alert, db_path)
                    if alert_id:
                        threat_intel.enrich_alert_background(alert_id, db_path)
                alerts_count += 1
                
                if show_progress:
                    pbar.set_postfix({'alerts': alerts_count, 'last': alert['rule_name'][:15]})
        
        if show_progress:
            pbar.close()
            logger.info(f"[✓] Processed {events_processed} events, generated {alerts_count} alerts")
            
        return {'total_events': events_processed, 'alerts_generated': alerts_count}
        
    except Exception as e:
        logger.error(f"Detection error: {e}")
        raise

def process_generic_log_file(
    file_path: str,
    db_path: str = None,
    rules_folder: str = "sigma_rules",
    file_type: str = 'json'
) -> Dict[str, int]:
    """Processes a generic JSON or CSV log file for threats.

    Args:
        file_path: Path to the log file.
        db_path: Path to the SQLite database (optional).
        rules_folder: Path to Sigma rules directory.
        file_type: Format of the file ('json' or 'csv').

    Returns:
        A dictionary with processing statistics.
    """
    if file_type == 'json':
        events = LogIngestor.parse_json(file_path)
    elif file_type == 'csv':
        events = LogIngestor.parse_csv(file_path)
    else:
        raise ValueError(f"Unsupported file type: {file_type}")
        
    rule_paths = list(Path(rules_folder).rglob("*.yml")) + list(Path(rules_folder).rglob("*.yaml"))
    compiled_rules = sigma_backend.compile_sigma_rules_from_files([str(p) for p in rule_paths])
    
    if db_path:
        import db
        db.init_db(db_path)

    alerts_count = 0
    for event in events:
        matched_results = []
        for rule_dict, matcher in compiled_rules:
            if matcher(event):
                matched_results.append(sigma_loader.get_rule_metadata_from_dict(rule_dict))
        
        if matched_results:
            alert = create_alert(event, matched_results, file_type)
            if db_path:
                import db
                alert_id = db.insert_alert(alert, db_path)
                if alert_id:
                    threat_intel.enrich_alert_background(alert_id, db_path)
            alerts_count += 1
            
    return {
        'total_events': len(events),
        'alerts_generated': alerts_count
    }


def main():
    """
    Main entry point for the detection engine.
    """
    parser = argparse.ArgumentParser(
        description="CyberThreatX - Windows EVTX Threat Detection Engine (Version 3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detect.py security.evtx --db cyberthreatx.db
  python detect.py security.evtx --rules-folder my_rules/
        """
    )
    
    parser.add_argument('evtx_file', type=str, help='Path to the EVTX file to analyze')
    parser.add_argument('--output', type=str, default=None, help='Output JSON file for alerts')
    parser.add_argument('--db', type=str, default=None, help='Path to SQLite database')
    parser.add_argument('--rules-folder', type=str, default="sigma_rules", help='Folder containing Sigma rules')
    
    args = parser.parse_args()
    
    try:
        file_path = Path(args.evtx_file)
        if file_path.suffix.lower() == '.evtx':
            process_evtx_file(
                evtx_file=args.evtx_file,
                db_path=args.db,
                json_output=args.output,
                rules_folder=args.rules_folder,
                show_progress=True
            )
        elif file_path.suffix.lower() in ['.json', '.csv']:
            file_type = file_path.suffix.lower()[1:]
            process_generic_log_file(
                file_path=args.evtx_file,
                db_path=args.db,
                rules_folder=args.rules_folder,
                file_type=file_type
            )
            logger.info(f"[✓] Processed generic {file_type} log: {args.evtx_file}")
        else:
            logger.error(f"Unsupported file extension: {file_path.suffix}")
            sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:
        sys.exit(1)


if __name__ == "__main__":
    main()
