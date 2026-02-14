import os
import uuid
import yaml

RULES_BASE = "sigma_rules/windows"

CATEGORIES = {
    "process_creation": [
        ("Suspicious Network Shell Usage", "netsh.exe", ["add helper", "trace start", "int portproxy"]),
        ("LOLBAS - Certification Authority Usage", "certutil.exe", ["-urlcache", "-split", "-decode"]),
        ("LOLBAS - BITSAdmin Job Creation", "bitsadmin.exe", ["/create", "/transfer", "/addfile"]),
        ("Credential Dumping - SAM/SYSTEM via Reg", "reg.exe", ["save hklm\\sam", "save hklm\\system", "save hklm\\security"]),
        ("Credential Dumping - LSASS via Taskmgr", "taskmgr.exe", ["/dump", "-dump"]),
        ("Persistence - Scheduled Task Creation", "schtasks.exe", ["/create /tn", "/create /xml"]),
        ("Defense Evasion - Firewall Rule Addition", "netsh.exe", ["advfirewall firewall add rule"]),
        ("Discovery - Network Configuration", "ipconfig.exe", ["/all", "/displaydns"]),
        ("Discovery - System Information", "systeminfo.exe", []),
        ("Discovery - Domain Information", "net.exe", ["group \"domain admins\" /domain", "user /domain"]),
        ("Lateral Movement - SMB Share Access", "net.exe", ["use \\\\", "share"]),
        ("Lateral Movement - WMIC Remote Execution", "wmic.exe", ["/node:", "process call create"]),
        ("Execution - InstallUtil Usage", "installutil.exe", ["/logfile=", "/u"]),
        ("Execution - Regasm/Regsvcs Usage", "regasm.exe", ["/U", "/codebase"]),
        ("Defense Evasion - Timestamp Manipulation", "timestomp.exe", []),
        ("Persistence - New User Creation", "net.exe", ["user /add", "localgroup administrators /add"]),
        ("LOLBAS - Regsvr32 Execution", "regsvr32.exe", ["/s", "/n", "/u", "/i:http"]),
        ("LOLBAS - Rundll32 Execution", "rundll32.exe", ["javascript:", "mshtml,RunHTMLApplication"]),
        ("LOLBAS - Mshta Execution", "mshta.exe", ["http", "vbscript", "javascript"]),
        ("Defense Evasion - Pcty Usage", "pcty.exe", []),
        ("Execution - GfxDownloadWrapper", "GfxDownloadWrapper.exe", ["http"]),
        ("Defense Evasion - MpCmdRun Usage", "MpCmdRun.exe", ["-DownloadFile"]),
        ("Execution - Mavinject Usage", "mavinject.exe", ["/INJECTRUNNING"]),
        ("Persistence - WMI Event Subscription", "wmic.exe", ["/namespace:\\\\root\\subscription", "EventFilter", "EventConsumer"])
    ],
    "powershell": [
        ("PowerShell Encoded Command", "powershell.exe", ["-enc", "-EncodedCommand"]),
        ("PowerShell Download String", "powershell.exe", ["DownloadString", "DownloadFile"]),
        ("PowerShell Web Request", "powershell.exe", ["Invoke-WebRequest", "iwr "]),
        ("PowerShell Empire Agent Keywords", "powershell.exe", ["Invoke-Empire", "Start-Empire"]),
        ("PowerShell Obfuscation - Backticks", "powershell.exe", ["`p`o`w`e`r"]),
        ("PowerShell Reflection Usage", "powershell.exe", ["Reflection.Assembly"]),
        ("PowerShell Script Block Logging Evasion", "powershell.exe", ["ScriptBlockLogging", "EnableBlockLogging"]),
        ("PowerShell IEX Usage", "powershell.exe", ["iex ", "Invoke-Expression"]),
        ("PowerShell Clipboard Access", "powershell.exe", ["Get-Clipboard", "Set-Clipboard"])
    ],
    "registry": [
        ("Registry Persistence - Run Key", "Regedit.exe", ["\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce"]),
        ("Registry Persistence - Image File Execution Options", "Regedit.exe", ["\\Image File Execution Options\\"]),
        ("Registry Persistence - Shell Icon Overlay Identifiers", "Regedit.exe", ["\\Shell Icon Overlay Identifiers\\"]),
        ("Registry - Disable Windows Defender", "reg.exe", ["\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring"]),
        ("Registry - Disable UAC", "reg.exe", ["\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA"]),
        ("Registry - New Service Creation", "reg.exe", ["\\CurrentControlSet\\Services\\", "ImagePath"])
    ],
    "sysmon": [
        ("Sysmon - Network Connection to Rare Port", "Network", ["DestinationPort: 4444", "DestinationPort: 8080", "DestinationPort: 1337"]),
        ("Sysmon - Process Injection via CreateRemoteThread", "CreateRemoteThread", []),
        ("Sysmon - Raw Access Read to Drive", "RawAccessRead", []),
        ("Sysmon - Named Pipe Creation", "PipeEvent", ["\\pipe\\psexec", "\\pipe\\lsass"]),
        ("Sysmon - Clipboard Change Detected", "Clipboard", []),
        ("Sysmon - DNS Query to Suspect Domain", "DnsQuery", ["QueryName: .top", "QueryName: .xyz", "QueryName: .pw"])
    ]
}

def generate_rules():
    count = 0
    for cat, rules in CATEGORIES.items():
        dir_path = os.path.join(RULES_BASE, cat)
        os.makedirs(dir_path, exist_ok=True)
        
        for title, image, keywords in rules:
            rule_id = str(uuid.uuid4())
            # Sanitize filename
            safe_title = title.lower().replace(' ', '_').replace('-', '_').replace('/', '_').replace('\\', '_')
            filename = f"gen_{cat}_{safe_title}.yml"
            file_path = os.path.join(dir_path, filename)
            
            # Basic Template
            rule = {
                "title": title,
                "id": rule_id,
                "status": "stable",
                "description": f"Generated rule for {title}",
                "author": "CyberThreatX Generator",
                "logsource": {
                    "product": "windows",
                    "category": cat if cat != "sysmon" else None,
                    "service": "sysmon" if cat == "sysmon" else None
                },
                "detection": {
                    "selection": {},
                    "condition": "selection"
                },
                "level": "medium",
                "tags": ["attack.generated"]
            }
            
            if cat == "process_creation":
                rule["detection"]["selection"]["Image|endswith"] = [f"\\{image}"]
                if keywords:
                    rule["detection"]["selection"]["CommandLine|contains"] = keywords
            elif cat == "powershell":
                rule["detection"]["selection"]["CommandLine|contains"] = [image] + keywords
            elif cat == "sysmon":
                if "EventID" not in rule["detection"]["selection"]:
                    rule["detection"]["selection"]["EventID"] = 1 # Default for proc creation if not specified
                if image == "CreateRemoteThread": rule["detection"]["selection"]["EventID"] = 8
                if image == "RawAccessRead": rule["detection"]["selection"]["EventID"] = 9
                if image == "PipeEvent": rule["detection"]["selection"]["EventID"] = 17
                if keywords:
                    rule["detection"]["selection"]["CommandLine|contains"] = keywords
            
            with open(file_path, "w") as f:
                yaml.dump(rule, f, sort_keys=False)
            count += 1
            
    print(f"Generated {count} total rules.")

if __name__ == "__main__":
    generate_rules()
