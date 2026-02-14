"""
Sigma Rule Loader for CyberThreatX
Recursively loads Sigma rules from YAML files.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any
from sigma.rule import SigmaRule


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


def load_sigma_rules(folder_path: str = "sigma_rules") -> List[SigmaRule]:
    """Recursively loads all Sigma rules from a folder.

    Args:
        folder_path: Path to the folder containing Sigma rule YAML files.

    Returns:
        A list of SigmaRule objects.
    """
    rules = []
    folder = Path(folder_path)
    
    # Check if folder exists
    if not folder.exists():
        logger.warning(f"Sigma rules folder not found: {folder_path}")
        logger.info(f"Creating folder: {folder_path}")
        folder.mkdir(parents=True, exist_ok=True)
        return rules
    
    # Find all .yml and .yaml files recursively
    yaml_files = list(folder.rglob("*.yml")) + list(folder.rglob("*.yaml"))
    
    if not yaml_files:
        logger.warning(f"No YAML files found in {folder_path}")
        return rules
    
    logger.info(f"Found {len(yaml_files)} YAML files in {folder_path}")
    
    # Load each file
    for yaml_file in yaml_files:
        try:
            # Read YAML content
            with open(yaml_file, 'r', encoding='utf-8') as f:
                yaml_content = f.read()
            
            # Parse as Sigma rule
            rule = SigmaRule.from_yaml(yaml_content)
            
            # Validate rule has required fields
            if not rule.title:
                logger.warning(f"Rule missing title: {yaml_file.name}")
                continue
            
            if not rule.detection:
                logger.warning(f"Rule missing detection logic: {yaml_file.name}")
                continue
            
            rules.append(rule)
            logger.debug(f"Loaded rule: {rule.title} ({yaml_file.name})")
            
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in {yaml_file.name}: {str(e)}")
            continue
            
        except Exception as e:
            logger.error(f"Error loading {yaml_file.name}: {str(e)}")
            continue
    
    logger.info(f"Successfully loaded {len(rules)} Sigma rules")
    return rules


def get_rule_metadata(rule: SigmaRule) -> Dict[str, Any]:
    """Extracts normalized metadata from a SigmaRule object.

    Args:
        rule: The SigmaRule object.

    Returns:
        A dictionary with standardized rule metadata.
    """
    metadata = {
        'title': rule.title or 'Untitled Rule',
        'id': str(rule.id) if rule.id else None,
        'description': rule.description or rule.title or '',
        'level': rule.level.name.lower() if rule.level else 'medium',
        'status': rule.status.name.lower() if rule.status else 'test',
        'tags': rule.tags or [],
        'author': rule.author or 'Unknown',
        'date': str(rule.date) if rule.date else None,
        'references': rule.references or [],
        'logsource': {
            'product': rule.logsource.product if rule.logsource else None,
            'service': rule.logsource.service if rule.logsource else None,
            'category': rule.logsource.category if rule.logsource else None,
        }
    }
    
    # Extract MITRE ATT&CK techniques from tags
    mitre_techniques = []
    for tag in metadata['tags']:
        tag_str = str(tag)  # Convert SigmaRuleTag to string
        if tag_str.startswith('attack.t'):
            # Extract technique ID (e.g., 'attack.t1059.001' -> 'T1059.001')
            technique = tag_str.replace('attack.t', 'T').upper()
            mitre_techniques.append(technique)
    
    metadata['mitre_techniques'] = mitre_techniques
    
    return metadata


def get_rule_metadata_from_dict(rule_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Extracts metadata from a Sigma rule dictionary (yaml-parsed).

    Args:
        rule_dict: The dictionary containing the rule fields.

    Returns:
        A dictionary with normalized rule metadata.
    """
    metadata = {
        'title': rule_dict.get('title', 'Untitled Rule'),
        'id': str(rule_dict.get('id', '')),
        'description': rule_dict.get('description', rule_dict.get('title', '')),
        'level': rule_dict.get('level', 'medium').lower(),
        'status': rule_dict.get('status', 'test').lower(),
        'tags': rule_dict.get('tags', []),
        'author': rule_dict.get('author', 'Unknown'),
        'date': str(rule_dict.get('date', '')),
        'references': rule_dict.get('references', []),
        'logsource': rule_dict.get('logsource', {})
    }
    
    # Extract MITRE ATT&CK techniques from tags
    mitre_techniques = []
    for tag in metadata['tags']:
        tag_str = str(tag)
        if tag_str.startswith('attack.t'):
            technique = tag_str.replace('attack.t', 'T').upper()
            mitre_techniques.append(technique)
    
    metadata['mitre_techniques'] = mitre_techniques
    
    return metadata


def validate_rule(rule: SigmaRule) -> bool:
    """
    Validate that a Sigma rule has required fields.
    
    Args:
        rule: SigmaRule object
        
    Returns:
        True if valid, False otherwise
    """
    if not rule.title:
        logger.warning("Rule missing title")
        return False
    
    if not rule.detection:
        logger.warning(f"Rule '{rule.title}' missing detection logic")
        return False
    
    return True


def print_rule_summary(rules: List[SigmaRule]) -> None:
    """
    Print a summary of loaded rules.
    
    Args:
        rules: List of SigmaRule objects
    """
    print("\n" + "=" * 80)
    print(f"Loaded {len(rules)} Sigma Rules")
    print("=" * 80)
    
    if not rules:
        print("No rules loaded.")
        return
    
    # Group by severity
    by_level = {}
    for rule in rules:
        level = rule.level.name.lower() if rule.level else 'medium'
        if level not in by_level:
            by_level[level] = []
        by_level[level].append(rule)
    
    # Print summary
    for level in ['critical', 'high', 'medium', 'low', 'informational']:
        if level in by_level:
            print(f"\n{level.upper()} ({len(by_level[level])} rules):")
            for rule in by_level[level]:
                metadata = get_rule_metadata(rule)
                mitre = f" [{', '.join(metadata['mitre_techniques'])}]" if metadata['mitre_techniques'] else ""
                print(f"  - {rule.title}{mitre}")
    
    print("\n" + "=" * 80)


def main():
    """
    Test the Sigma rule loader.
    """
    print("=" * 80)
    print("CyberThreatX - Sigma Rule Loader Test")
    print("=" * 80)
    
    # Load rules
    rules = load_sigma_rules("sigma_rules")
    
    # Print summary
    print_rule_summary(rules)
    
    # Print detailed info for first rule
    if rules:
        print("\nExample Rule Details:")
        print("-" * 80)
        first_rule = rules[0]
        metadata = get_rule_metadata(first_rule)
        
        print(f"Title: {metadata['title']}")
        print(f"Description: {metadata['description']}")
        print(f"Level: {metadata['level']}")
        print(f"Status: {metadata['status']}")
        print(f"Author: {metadata['author']}")
        print(f"Tags: {', '.join(str(t) for t in metadata['tags'])}")
        print(f"MITRE Techniques: {', '.join(metadata['mitre_techniques']) if metadata['mitre_techniques'] else 'None'}")
        print(f"Log Source: {metadata['logsource']}")
        print("-" * 80)


if __name__ == "__main__":
    main()
