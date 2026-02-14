"""
EVTX Parser Module
Provides functionality to parse Windows EVTX files and extract normalized event data.
"""

import sys
import warnings
from datetime import datetime
from typing import Generator, Dict, Any, Optional
import Evtx.Evtx as evtx
import xmltodict


def parse_evtx(file_path: str) -> Generator[Dict[str, Any], None, None]:
    """
    Parse an EVTX file and yield normalized event dictionaries.
    
    Args:
        file_path: Path to the .evtx file
        
    Yields:
        Dictionary containing normalized event data with fields:
        - EventID (int): The event identifier
        - TimeCreated (str): ISO format timestamp
        - Computer (str): Computer name
        - Provider (str): Event provider name
        - EventData (dict): Flattened event data as key-value pairs
        - Channel (str, optional): Event channel (e.g., Security, System)
        - Level (int, optional): Event level
    """
    try:
        with evtx.Evtx(file_path) as log:
            for record in log.records():
                try:
                    # Parse the XML content of the event
                    xml_content = record.xml()
                    event_dict = xmltodict.parse(xml_content)
                    
                    # Navigate to the Event element
                    event = event_dict.get('Event', {})
                    system = event.get('System', {})
                    event_data = event.get('EventData', {})
                    
                    # Extract EventID
                    event_id_raw = system.get('EventID')
                    if isinstance(event_id_raw, dict):
                        event_id = event_id_raw.get('#text')
                        if event_id is not None:
                            event_id = int(event_id)
                    else:
                        event_id = int(event_id_raw) if event_id_raw is not None else None
                    
                    # Extract TimeCreated
                    time_created_raw = system.get('TimeCreated', {})
                    if isinstance(time_created_raw, dict):
                        time_created = time_created_raw.get('@SystemTime', '')
                    else:
                        time_created = str(time_created_raw) if time_created_raw else ''
                    
                    # Extract Computer
                    computer = system.get('Computer', 'Unknown')
                    
                    # Extract Provider
                    provider_raw = system.get('Provider', {})
                    if isinstance(provider_raw, dict):
                        provider = provider_raw.get('@Name', 'Unknown')
                    else:
                        provider = str(provider_raw) if provider_raw else 'Unknown'
                    
                    # Extract Channel
                    channel = system.get('Channel', '')
                    
                    # Extract Level
                    level_raw = system.get('Level', None)
                    level = int(level_raw) if level_raw is not None else None
                    
                    # Flatten EventData
                    flattened_event_data = {}
                    if event_data:
                        data_items = event_data.get('Data', [])
                        
                        # Handle case where Data is a single item (not a list)
                        if isinstance(data_items, dict):
                            data_items = [data_items]
                        
                        # Flatten data items
                        if isinstance(data_items, list):
                            for item in data_items:
                                if isinstance(item, dict):
                                    name = item.get('@Name', 'UnnamedField')
                                    value = item.get('#text', '')
                                    
                                    # Handle duplicate keys by converting to list
                                    if name in flattened_event_data:
                                        existing = flattened_event_data[name]
                                        if isinstance(existing, list):
                                            existing.append(value)
                                        else:
                                            flattened_event_data[name] = [existing, value]
                                    else:
                                        flattened_event_data[name] = value
                    
                    # Build normalized event dictionary
                    normalized_event = {
                        'EventID': event_id,
                        'TimeCreated': time_created,
                        'Computer': computer,
                        'Provider': provider,
                        'EventData': flattened_event_data,
                        'Channel': channel,
                    }
                    
                    # Add Level only if it exists
                    if level is not None:
                        normalized_event['Level'] = level
                    
                    yield normalized_event
                    
                except Exception as e:
                    # Log warning for malformed events and continue
                    warnings.warn(f"Failed to parse event record: {str(e)}", UserWarning)
                    continue
                    
    except FileNotFoundError:
        raise FileNotFoundError(f"EVTX file not found: {file_path}")
    except Exception as e:
        raise RuntimeError(f"Error opening EVTX file {file_path}: {str(e)}")


if __name__ == "__main__":
    """
    Demonstration: Parse an EVTX file and print the first 5 events.
    Usage: python evtx_parser.py <path_to_evtx_file>
    """
    if len(sys.argv) < 2:
        print("Usage: python evtx_parser.py <path_to_evtx_file>", file=sys.stderr)
        sys.exit(1)
    
    evtx_file = sys.argv[1]
    
    print(f"Parsing EVTX file: {evtx_file}\n")
    print("=" * 80)
    
    try:
        event_count = 0
        for event in parse_evtx(evtx_file):
            event_count += 1
            print(f"\nEvent #{event_count}:")
            print(f"  EventID: {event['EventID']}")
            print(f"  TimeCreated: {event['TimeCreated']}")
            print(f"  Computer: {event['Computer']}")
            print(f"  Provider: {event['Provider']}")
            print(f"  Channel: {event.get('Channel', 'N/A')}")
            print(f"  Level: {event.get('Level', 'N/A')}")
            print(f"  EventData: {event['EventData']}")
            print("-" * 80)
            
            if event_count >= 5:
                break
        
        print(f"\nDisplayed first {event_count} event(s).")
        
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
