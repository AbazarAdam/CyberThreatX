# CyberThreatX: A Modern SOC-in-a-Box Solution
**Final Project Report**

## 1. Executive Summary
CyberThreatX is a comprehensive security monitoring and incident response platform designed to bridge the gap between complex enterprise SIEMs and lightweight log parsers. By integrating standardized Sigma rules with behavioral anomaly detection, CyberThreatX provides real-time visibility into Windows environments and generic log streams.

## 2. Motivation and Goals
The primary goal was to build a tool that showcases:
- **Scalability**: Handling diverse log formats (EVTX, JSON, CSV, Syslog).
- **Automation**: Reducing analyst fatigue through automated correlation and threat intel enrichment.
- **Portability**: A single-repo solution that can be deployed via Docker in minutes.
- **Modern Standards**: Adherence to the Sigma specification and MITRE ATT&CK framework.

## 3. Core Capabilities

### 3.1 Advanced Detection Engine
The engine utilizes a custom-built Sigma backend that translates YAML detection logic into efficient Python execution paths. This allows security researchers to use the global library of Sigma rules without needing complex infrastructure.

### 3.2 Machine Learning & Baselining
Unlike traditional signature-based systems, CyberThreatX includes an ML engine that:
- Establishes a baseline of "normal" activity per host.
- Identifies volume-based anomalies (e.g., sudden spikes in failed logins).
- Scores incidents on a scale of 0.0 to 1.0 to help prioritize high-risk events.

### 3.3 Correlation & Deduplication
To combat "alert fatigue," the system automatically correlate related alerts. For example, multiple failed login attempts on a single host are grouped into a "Brute Force Detected" incident, significantly reducing the noise in the dashboard.

### 3.4 Threat Intelligence Enrichment
Integration with AlienVault OTX ensures that indicators of compromise (IOCs) such as suspicious IP addresses are automatically flagged with reputation data, providing analysts with instant context.

## 4. Technical Architecture
The system is built on a modular Python architecture:
- **Backend**: Python 3.8+ with Flask.
- **Persistence**: SQLite (optimized with WAL mode for concurrency).
- **Ingestion**: Watchdog for real-time file monitoring.
- **Frontend**: Clean, responsive HTML/CSS with a focus on analyst workflows.

## 5. Challenges & Solutions

| Challenge | Solution |
| :--- | :--- |
| **EventID Normalization** | Developed a recursive extraction logic to handle various EVTX and JSON nested structures. |
| **Database Concurrency** | Implemented SQLite WAL mode and a robust context manager to prevent locking during high-volume ingestion. |
| **Sigma Mapping** | Created a simplified translation layer to support complex field modifiers like `|contains` and `|re`. |
| **Duplicate Alerts** | Disabled legacy hardcoded rules in favor of the Sigma engine and added a normalization step in the watcher. |

## 6. Testing & Validation
The system was validated using:
- **Atomic Red Team**: Simulating T1059.001 (PowerShell Execution) and T1003 (OS Credential Dumping).
- **Sample Datasets**: Ingestion of EVTX samples from the EVTX-ATTACK-SAMPLES project.
- **Performance Benchmarking**: Verified processing of 10,000+ events per minute on standard hardware.

## 7. Future Work
- **Live Windows Event Forwarding (WEF)**: Native support for Windows Event Logs over network.
- **Advanced Visualization**: Interactive relationship graphs for IOCs.
- **Cloud Integration**: AWS CloudWatch and Azure Monitor ingestion modules.

## 8. Conclusion
CyberThreatX demonstrates that a powerful security operations center can be built with open-source tools and thoughtful engineering. It stands as a testament to the effectiveness of standardized detection logic and automated triage in modern cybersecurity.

---
**Author**: [Your Name]
**Date**: February 2026
**Version**: 4.0
