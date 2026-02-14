"""
Utility Functions
Helper functions for CyberThreatX.
"""

from typing import Any, Dict
import json


import logging

logger = logging.getLogger(__name__)

def pretty_print_json(data: Dict[str, Any], indent: int = 2) -> str:
    """Formats a dictionary as a pretty-printed JSON string.

    Args:
        data: The dictionary to format.
        indent: Number of spaces for indentation.

    Returns:
        A beautifully formatted JSON string.
    """
    return json.dumps(data, indent=indent, ensure_ascii=False)


def safe_get(dictionary: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Safely retrieves a nested value from a dictionary.

    Args:
        dictionary: The source dictionary.
        *keys: Variable sequence of keys to traverse.
        default: Value to return if any key is missing.

    Returns:
        The nested value or the default if traversal fails.
    """
    current = dictionary
    
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
            if current is None:
                return default
        else:
            return default
    
    return current if current is not None else default


def flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """Flattens a deeply nested dictionary into a single level.

    Args:
        d: The nested dictionary.
        parent_key: Prefix for generated keys (used recursively).
        sep: Separator between key levels.

    Returns:
        A flattened version of the input dictionary.
    """
    items = []
    
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    
    return dict(items)


if __name__ == "__main__":
    """
    Demonstration of utility functions.
    """
    # Test data
    test_dict = {
        'System': {
            'EventID': {
                '#text': '4625'
            },
            'Computer': 'TEST-PC'
        },
        'EventData': {
            'TargetUserName': 'admin',
            'IpAddress': '192.168.1.100'
        }
    }
    
    print("Utility Functions Demo")
    print("=" * 80)
    
    # Test pretty_print_json
    print("\n1. Pretty Print JSON:")
    print(pretty_print_json(test_dict))
    
    # Test safe_get
    print("\n2. Safe Get:")
    print(f"  EventID: {safe_get(test_dict, 'System', 'EventID', '#text', default='N/A')}")
    print(f"  Computer: {safe_get(test_dict, 'System', 'Computer', default='N/A')}")
    print(f"  NonExistent: {safe_get(test_dict, 'NonExistent', 'Key', default='N/A')}")
    
    # Test flatten_dict
    print("\n3. Flatten Dictionary:")
    flattened = flatten_dict(test_dict)
    print(pretty_print_json(flattened))
    
    print("\n" + "=" * 80)
