"""
Simplified Sigma Backend for CyberThreatX
Translates Sigma rules into Python matcher functions using direct YAML parsing.
"""

import re
import yaml
import logging
from typing import Callable, List, Tuple, Dict, Any


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class SimpleSigmaBackend:
    """Provides a simplified Sigma backend translation to Python matchers."""
    
    def __init__(self):
        """Initializes the backend with a function cache."""
        self.compiled_cache = {}
    
    def compile_rule_from_yaml(self, rule_yaml: str, rule_title: str = "Unknown") -> Callable[[Dict[str, Any]], bool]:
        """
        Compile a Sigma rule from YAML string into a Python matcher function.
        
        Args:
            rule_yaml: YAML string containing the rule
            rule_title: Rule title for logging
            
        Returns:
            Callable that takes an event dict and returns True if matched
        """
        try:
            # Parse YAML
            rule_dict = yaml.safe_load(rule_yaml)
            
            if 'detection' not in rule_dict:
                logger.error(f"Rule '{rule_title}' missing detection section")
                return lambda event: False
            
            detection = rule_dict['detection']
            condition = detection.get('condition', 'selection')
            
            # Build matcher
            return self._build_matcher_from_detection(detection, condition, rule_title)
            
        except Exception as e:
            logger.error(f"Error compiling rule '{rule_title}': {str(e)}", exc_info=True)
            return lambda event: False
    
    def _build_matcher_from_detection(self, detection: Dict, condition: str, rule_title: str) -> Callable:
        """
        Build a matcher function from detection dictionary.
        
        Args:
            detection: Detection dictionary from YAML
            condition: Condition string
            rule_title: Rule title for logging
            
        Returns:
            Callable matcher function
        """
        # Build matchers for each selection
        selection_matchers = {}
        
        for key, value in detection.items():
            if key == 'condition':
                continue
            
            # Build matcher for this selection
            selection_matchers[key] = self._build_selection_matcher(value)
        
        # Build condition evaluator
        def matcher(event: Dict[str, Any]) -> bool:
            """Evaluate the rule against an event."""
            try:
                # Evaluate each selection
                results = {}
                for name, sel_matcher in selection_matchers.items():
                    results[name] = sel_matcher(event)
                
                # Evaluate condition
                return self._evaluate_condition(condition, results)
                
            except Exception as e:
                logger.debug(f"Error evaluating rule '{rule_title}': {str(e)}")
                return False
        
        return matcher
    
    def _build_selection_matcher(self, selection: Any) -> Callable:
        """
        Build a matcher for a selection.
        
        Args:
            selection: Selection value (dict, list, or primitive)
            
        Returns:
            Callable matcher function
        """
        if isinstance(selection, dict):
            # Dictionary of field: value pairs
            # All must match (AND logic)
            field_matchers = []
            for field, value in selection.items():
                field_matchers.append(self._build_field_matcher(field, value))
            
            return lambda event: all(m(event) for m in field_matchers)
        
        if isinstance(selection, list):
            # List of selections - OR logic
            matchers = [self._build_selection_matcher(s) for s in selection]
            return lambda event: any(m(event) for m in matchers)
        
        else:
            # Single value - always false
            return lambda event: False
    
    def _build_field_matcher(self, field: str, value: Any) -> Callable:
        """
        Build a matcher for a single field.
        
        Args:
            field: Field name
            value: Expected value(s)
            
        Returns:
            Callable matcher function
        """
        # Handle modifiers (e.g., "CommandLine|contains")
        if '|' in field:
            field_name, modifier = field.split('|', 1)
            return self._build_modified_field_matcher(field_name, modifier, value)
        
        # Handle multiple values (OR logic)
        if isinstance(value, list):
            return lambda event: any(
                self._match_field_value(event, field, v) for v in value
            )
        
        # Single value
        return lambda event: self._match_field_value(event, field, value)
    
    def _build_modified_field_matcher(self, field: str, modifier: str, value: Any) -> Callable:
        """
        Build a matcher for a field with modifiers.
        
        Args:
            field: Field name
            modifier: Modifier (e.g., "contains", "startswith", "endswith", "re")
            value: Expected value(s)
            
        Returns:
            Callable matcher function
        """
        if modifier == 'contains':
            if isinstance(value, list):
                return lambda event: any(
                    self._field_contains(event, field, v) for v in value
                )
            return lambda event: self._field_contains(event, field, value)
        
        elif modifier == 'startswith':
            if isinstance(value, list):
                return lambda event: any(
                    self._field_startswith(event, field, v) for v in value
                )
            return lambda event: self._field_startswith(event, field, value)
        
        elif modifier == 'endswith':
            if isinstance(value, list):
                return lambda event: any(
                    self._field_endswith(event, field, v) for v in value
                )
            return lambda event: self._field_endswith(event, field, value)
        
        elif modifier == 're':
            if isinstance(value, list):
                return lambda event: any(
                    self._field_regex(event, field, v) for v in value
                )
            return lambda event: self._field_regex(event, field, value)
        
        else:
            # Unknown modifier - fall back to exact match
            logger.warning(f"Unknown modifier '{modifier}', using exact match")
            return lambda event: self._match_field_value(event, field, value)
    
    def _match_field_value(self, event: Dict[str, Any], field: str, value: Any) -> bool:
        """Match a field against a value (exact or wildcard)."""
        event_value = self._get_field_value(event, field)
        
        if event_value is None:
            return False
        
        event_str = str(event_value)
        value_str = str(value)
        
        # Check for wildcards
        if '*' in value_str or '?' in value_str:
            pattern = value_str.replace('*', '.*').replace('?', '.')
            pattern = f'^{pattern}$'
            return bool(re.match(pattern, event_str, re.IGNORECASE))
        
        # Exact match (case-insensitive)
        return event_str.lower() == value_str.lower()
    
    def _field_contains(self, event: Dict[str, Any], field: str, value: Any) -> bool:
        """Check if field contains value."""
        event_value = self._get_field_value(event, field)
        if event_value is None:
            return False
        return str(value).lower() in str(event_value).lower()
    
    def _field_startswith(self, event: Dict[str, Any], field: str, value: Any) -> bool:
        """Check if field starts with value."""
        event_value = self._get_field_value(event, field)
        if event_value is None:
            return False
        return str(event_value).lower().startswith(str(value).lower())
    
    def _field_endswith(self, event: Dict[str, Any], field: str, value: Any) -> bool:
        """Check if field ends with value."""
        event_value = self._get_field_value(event, field)
        if event_value is None:
            return False
        return str(event_value).lower().endswith(str(value).lower())
    
    def _field_regex(self, event: Dict[str, Any], field: str, pattern: str) -> bool:
        """Check if field matches regex pattern."""
        event_value = self._get_field_value(event, field)
        if event_value is None:
            return False
        return bool(re.search(pattern, str(event_value), re.IGNORECASE))
    
    def _get_field_value(self, event: Dict[str, Any], field: str) -> Any:
        """Gets a field value from an event, supporting aliases and nesting.
        """
        # Define common field aliases
        ALIASES = {
            'commandline': ['commandlinevalue', 'scriptblocktext', 'description'],
            'image': ['processimage', 'newprocessname', 'imageloaded'],
            'parentimage': ['parentprocessname'],
            'user': ['subjectusername', 'targetusername'],
            'logonid': ['subjectlogonid', 'targetlogonid'],
            'targetfilename': ['targetfile', 'filepath'],
            'destinationport': ['destport', 'port'],
            'destinationhostname': ['desthost'],
            'sourceport': ['srcport']
        }

        target_field = field.lower()
        search_fields = [target_field]
        if target_field in ALIASES:
            search_fields.extend(ALIASES[target_field])

        for f in search_fields:
            val = self._find_field_in_event(event, f)
            if val is not None:
                return val
        
        return None

    def _find_field_in_event(self, event: Dict[str, Any], target_field: str) -> Any:
        """Helper to find a potentially nested field in an event."""
        # 1. Try direct access in root (case-insensitive)
        for k, v in event.items():
            if k.lower() == target_field:
                return v

        # 2. Try EventData / event_data (common in Sysmon/Windows JSON)
        event_data = event.get('EventData') or event.get('event_data')
        if isinstance(event_data, dict):
            for k, v in event_data.items():
                if k.lower() == target_field:
                    return v

        # 3. Try nested dot-notation access
        if '.' in target_field:
            parts = target_field.split('.')
            current = event
            for part in parts:
                if not isinstance(current, dict):
                    break
                
                # Case-insensitive part match
                match_found = False
                for k, v in current.items():
                    if k.lower() == part:
                        current = v
                        match_found = True
                        break
                
                if not match_found:
                    # Try EventData if at root and first part didn't match
                    if current == event and (event.get('EventData') or event.get('event_data')):
                        ed = event.get('EventData') or event.get('event_data')
                        if isinstance(ed, dict):
                            for k, v in ed.items():
                                if k.lower() == part:
                                    current = v
                                    match_found = True
                                    break
                    
                    if not match_found:
                        return None
            return current

        return None
    
    def _evaluate_condition(self, condition: str, results: Dict[str, bool]) -> bool:
        """Evaluates a Sigma condition string against selection results.

        Args:
            condition: The condition string (e.g., "selection1 and not selection2").
            results: Dictionary mapping selection names to boolean results.

        Returns:
            Boolean result of the condition evaluation.
        """
        condition = condition.lower().strip()
        
        # Simple selection name
        if condition in results:
            return results[condition]
        
        # Handle "not X"
        if condition.startswith('not '):
            inner = condition[4:].strip()
            return not self._evaluate_condition(inner, results)
        
        # Handle "1 of X*" or "all of X" (Simplified)
        if 'all of ' in condition:
            prefix = condition.replace('all of ', '').strip().rstrip('*')
            relevant = [v for k, v in results.items() if k.startswith(prefix)]
            return all(relevant) if relevant else False
            
        if '1 of ' in condition:
            prefix = condition.replace('1 of ', '').strip().rstrip('*')
            relevant = [v for k, v in results.items() if k.startswith(prefix)]
            return any(relevant) if relevant else False

        # Handle "X and Y"
        if ' and ' in condition:
            parts = condition.split(' and ')
            return all(self._evaluate_condition(p.strip(), results) for p in parts)
        
        # Handle "X or Y"
        if ' or ' in condition:
            parts = condition.split(' or ')
            return any(self._evaluate_condition(p.strip(), results) for p in parts)
        
        # Handle parentheses
        if '(' in condition:
            # Very basic paren removal - real parser needed for complex ones
            condition = condition.replace('(', '').replace(')', '')
            return self._evaluate_condition(condition, results)
        
        if condition not in results:
            logger.debug(f"Condition term '{condition}' not found in results: {list(results.keys())}")
            
        return results.get(condition, False)


def compile_sigma_rules_from_files(rule_files: List[str]) -> List[Tuple[Dict, Callable]]:
    """
    Compile Sigma rules from YAML files.
    
    Args:
        rule_files: List of paths to YAML files
        
    Returns:
        List of (rule_dict, matcher_function) tuples
    """
    backend = SimpleSigmaBackend()
    compiled = []
    
    for rule_file in rule_files:
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule_yaml = f.read()
            
            rule_dict = yaml.safe_load(rule_yaml)
            title = rule_dict.get('title', 'Unknown')
            
            # Actually compile the rule
            matcher = backend.compile_rule_from_yaml(rule_yaml, title)
            compiled.append((rule_dict, matcher))
            
        except Exception as e:
            logger.error(f"Failed to compile rule from {rule_file}: {e}", exc_info=True)
            continue
    
    logger.info(f"Compiled {len(compiled)} rules")
    return compiled


def test_backend():
    """Test the Sigma backend."""
    print("=" * 80)
    print("Simplified Sigma Backend Test")
    print("=" * 80)
    
    # Test rule
    test_rule_yaml = """
title: Test Failed Logon
id: 12345678-1234-1234-1234-123456789012
status: test
description: Detects failed logon attempts
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
level: medium
tags:
    - attack.t1110
"""
    
    # Compile it
    backend = SimpleSigmaBackend()
    matcher = backend.compile_rule_from_yaml(test_rule_yaml, "Test Failed Logon")
    
    # Test events
    test_events = [
        {'EventID': 4625, 'Computer': 'TEST-PC'},
        {'EventID': 4624, 'Computer': 'TEST-PC'},
        {'EventID': 4625, 'Computer': 'OTHER-PC'}
    ]
    
    print(f"\nTesting rule: Test Failed Logon")
    print("-" * 80)
    
    for i, event in enumerate(test_events, 1):
        result = matcher(event)
        status = "✓ MATCH" if result else "✗ NO MATCH"
        print(f"Event {i} (EventID {event['EventID']}): {status}")
    
    print("\n" + "=" * 80)
    print("✓ Backend test complete!")
    print("=" * 80)


if __name__ == "__main__":
    test_backend()
