"""
File Watcher Module for CyberThreatX
Monitors a folder for new EVTX files and processes them automatically.
"""

import os
import sys
import time
import logging
import argparse
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import db
import config
from log_ingest import LogIngestor, start_syslog_server
import correlation


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class EVTXFileHandler(FileSystemEventHandler):
    """
    Handles file system events for EVTX files.
    """
    
    def __init__(self, db_path: str, rules_folder: str, process_callback):
        """Initializes the EVTX file handler.

        Args:
            db_path: Path to the SQLite database.
            rules_folder: Path to the folder containing Sigma rules.
            process_callback: Function to call when a new file is detected.
        """
        self.db_path = db_path
        self.rules_folder = rules_folder
        self.process_callback = process_callback
        self.processing = set()  # Track files currently being processed
    
    def on_created(self, event):
        """Triggered when a new file or directory is created in the watch path.

        Args:
            event: The watchdog file system event.
        """
        if event.is_directory:
            return
        
        # Check if it's a supported log file
        ext = event.src_path.lower().split('.')[-1]
        if ext not in ['evtx', 'json', 'csv']:
            return
        
        # Normalize path
        src_path = os.path.abspath(event.src_path)
        
        # Avoid processing the same file multiple times
        if src_path in self.processing:
            return
        
        logger.info(f"Detected new EVTX file: {event.src_path}")
        
        # Mark as processing
        self.processing.add(event.src_path)
        
        # Wait for file to be fully written (2 seconds)
        logger.info(f"Waiting 2 seconds for file to be fully written...")
        time.sleep(2)
        
        # Process the file
        try:
            self.process_callback(event.src_path, self.db_path, self.rules_folder)
        except Exception as e:
            logger.error(f"Error processing {event.src_path}: {str(e)}")
        finally:
            # Remove from processing set
            self.processing.discard(event.src_path)


def process_event_wrapper(event: Dict[str, Any], db_path: str, rules_folder: str):
    """Process a single normalized event."""
    from detect import run_detection_on_event
    try:
        run_detection_on_event(event, db_path, rules_folder)
    except Exception as e:
        logger.error(f"Error processing singleton event: {str(e)}")

def process_file_wrapper(evtx_path: str, db_path: str, rules_folder: str):
    """Wrapper to process any supported log file (EVTX, JSON, CSV).

    Args:
        evtx_path: Path to the file to process.
        db_path: Path to the SQLite database.
        rules_folder: Folder containing Sigma rules.
    """
    logger.info(f"Processing file: {evtx_path}")
    
    try:
        from detect import process_evtx_file, process_generic_log_file
        
        db.init_db(db_path)
        
        ext = evtx_path.lower().split('.')[-1]
        
        if ext == 'evtx':
            stats = process_evtx_file(evtx_path, db_path=db_path, rules_folder=rules_folder)
        else:
            stats = process_generic_log_file(evtx_path, db_path=db_path, rules_folder=rules_folder, file_type=ext)
        
        logger.info(f"✓ Processed {stats['total_events']} events, generated {stats['alerts_generated']} alerts")
        
        # Run correlation after file processing
        if stats['alerts_generated'] > 0:
            correlation.run_correlation_cycle(db_path)
        
    except Exception as e:
        logger.error(f"Error during processing: {str(e)}")
        raise


def start_watcher(watch_dir: str, db_path: str, rules_folder: str):
    """Starts the real-time file system watcher.

    Args:
        watch_dir: The directory to monitor.
        db_path: Path to the database for alert storage.
        rules_folder: Path to the Sigma rules library.
    """
    # Create watch directory if it doesn't exist
    Path(watch_dir).mkdir(parents=True, exist_ok=True)
    
    # Initialize database
    logger.info(f"Initializing database: {db_path}")
    db.init_db(db_path)
    
    # Create event handler
    event_handler = EVTXFileHandler(db_path, rules_folder, process_file_wrapper)
    
    # Create observer
    observer = Observer()
    observer.schedule(event_handler, watch_dir, recursive=False)
    
    # Start Syslog server if enabled
    if config.SYSLOG_ENABLED:
        start_syslog_server(config.SYSLOG_HOST, config.SYSLOG_PORT, lambda e: process_event_wrapper(e, db_path, rules_folder))

    logger.info(f"🔍 Starting file watcher...")
    logger.info(f"📁 Watching directory: {os.path.abspath(watch_dir)}")
    logger.info(f"💾 Database: {os.path.abspath(db_path)}")
    if config.SYSLOG_ENABLED:
        logger.info(f"📡 Syslog: Listening on {config.SYSLOG_HOST}:{config.SYSLOG_PORT}")
    logger.info(f"⏸️  Press Ctrl+C to stop")
    logger.info("=" * 80)
    
    # Start observer
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\n🛑 Stopping file watcher...")
        observer.stop()
    
    observer.join()
    logger.info("✓ File watcher stopped")


def main():
    """
    Main entry point for the watcher.
    """
    parser = argparse.ArgumentParser(
        description="CyberThreatX - Real-time EVTX File Watcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python watcher.py
  python watcher.py --watch-dir /path/to/logs --db custom.db
  
The watcher will monitor the specified directory for new .evtx files
and automatically process them using the CyberThreatX detection engine.
        """
    )
    
    parser.add_argument(
        '--watch-dir',
        type=str,
        default='monitored_logs',
        help='Directory to watch for new EVTX files (default: monitored_logs)'
    )
    
    parser.add_argument(
        '--db',
        type=str,
        default='cyberthreatx.db',
        help='Path to SQLite database (default: cyberthreatx.db)'
    )
    
    parser.add_argument(
        '--rules-folder',
        type=str,
        default='sigma_rules',
        help='Folder containing Sigma rules (default: sigma_rules)'
    )
    
    args = parser.parse_args()
    
    # Start watcher with rules-folder support
    # We need to update start_watcher as well to pass rules-folder
    start_watcher(args.watch_dir, args.db, args.rules_folder)


if __name__ == "__main__":
    main()
