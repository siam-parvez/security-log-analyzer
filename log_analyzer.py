#!/usr/bin/env python3
"""
Security Log Analyzer - Professional Version
Author: Siam Parvez
Date: May 2026
Purpose: Parse security logs, extract IOCs, generate multiple report formats

Usage:
    python3 log_analyzer.py --file sample.log --format json
    python3 log_analyzer.py --file sample.log --format html --output report.html
    python3 log_analyzer.py --help
"""

import re
import json
import argparse
import sys
from datetime import datetime
from pathlib import Path

# ============================================================
# CONFIGURATION
# ============================================================

# Severity levels to look for
SEVERITY_KEYWORDS = {
    "CRITICAL": 4,
    "ERROR": 3,
    "WARNING": 2,
    "INFO": 1,
    "DEBUG": 0
}

# Suspicious patterns (IOCs)
SUSPICIOUS_PATTERNS = {
    "password_spray": r"(failed login|authentication failure).*(from|ip)",
    "command_injection": r"(cat /etc/passwd|id;|whoami|nc -e|bash -i)",
    "port_scan": r"(port scan|nmap|masscan|multiple connection attempts)",
    "sql_injection": r"(union select|' or '1'='1|-- |; drop table)",
    "xss_attempt": r"(<script|onerror=|javascript:|alert\()",
    "privilege_escalation": r"(sudo su|su -|chmod 777|chown)",
    "data_exfil": r"(curl.*http|wget.*http|post.*http|base64 -d)"
}

# ============================================================
# LOG PARSING FUNCTIONS
# ============================================================

def parse_timestamp(line):
    """Extract timestamp if present (supports multiple formats)"""
    patterns = [
        r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}',
        r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',
        r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group()
    return "Unknown"

def extract_ip_addresses(text):
    """Extract all IPv4 addresses"""
    pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(pattern, text)
    # Filter out invalid IPs (like 999.999.999.999)
    valid_ips = []
    for ip in ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            valid_ips.append(ip)
    return list(set(valid_ips))

def get_severity(line):
    """Determine severity level based on keywords"""
    line_upper = line.upper()
    for severity, score in SEVERITY_KEYWORDS.items():
        if severity in line_upper:
            return severity, score
    return "UNKNOWN", -1

def detect_suspicious_activity(line):
    """Check line against known suspicious patterns"""
    detected = []
    line_lower = line.lower()
    for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, line_lower, re.IGNORECASE):
            detected.append(pattern_name)
    return detected

def parse_log_line(line, line_number):
    """Parse a single log line and return structured data"""
    return {
        "line_number": line_number,
        "raw": line.strip(),
        "timestamp": parse_timestamp(line),
        "severity": get_severity(line)[0],
        "severity_score": get_severity(line)[1],
        "ip_addresses": extract_ip_addresses(line),
        "suspicious": detect_suspicious_activity(line)
    }

# ============================================================
# ANALYSIS FUNCTIONS
# ============================================================

def analyze_log_file(file_path):
    """Main analysis function"""
    if not Path(file_path).exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    
    results = {
        "metadata": {
            "file": file_path,
            "analyzed_at": datetime.now().isoformat(),
            "total_lines": len(lines),
            "analyzer_version": "1.0.0"
        },
        "summary": {
            "severity_counts": {s: 0 for s in SEVERITY_KEYWORDS.keys()},
            "total_ips": 0,
            "unique_ips": [],
            "suspicious_events": [],
            "severity_score_total": 0
        },
        "details": []
    }
    
    all_ips = set()
    
    for i, line in enumerate(lines, 1):
        parsed = parse_log_line(line, i)
        results["details"].append(parsed)
        
        # Update summary counts
        severity = parsed["severity"]
        if severity in results["summary"]["severity_counts"]:
            results["summary"]["severity_counts"][severity] += 1
        
        # Track IPs
        for ip in parsed["ip_addresses"]:
            all_ips.add(ip)
        
        # Track suspicious events
        if parsed["suspicious"]:
            results["summary"]["suspicious_events"].append({
                "line": i,
                "patterns": parsed["suspicious"],
                "text": parsed["raw"][:100]
            })
        
        # Track severity score
        results["summary"]["severity_score_total"] += parsed["severity_score"]
    
    results["summary"]["unique_ips"] = list(all_ips)
    results["summary"]["total_ips"] = len(all_ips)
    
    return results

# ============================================================
# REPORT GENERATORS
# ============================================================

def generate_text_report(results):
    """Generate plain text report"""
    s = results["summary"]
    m = results["metadata"]
    
    report = f"""
{'='*60}
SECURITY LOG ANALYSIS REPORT
{'='*60}

METADATA
--------
File: {m['file']}
Analyzed: {m['analyzed_at']}
Total lines: {m['total_lines']}

SEVERITY SUMMARY
----------------
"""
    for severity, count in s["severity_counts"].items():
        bar = "█" * min(count, 20)
        report += f"{severity:10} : {count:4} {bar}\n"
    
    report += f"""
IP ADDRESSES FOUND
-----------------
Total unique IPs: {s['total_ips']}
{chr(10).join(['  • ' + ip for ip in s['unique_ips']]) if s['unique_ips'] else '  None'}

SUSPICIOUS EVENTS
-----------------
"""
    if s["suspicious_events"]:
        for event in s["suspicious_events"]:
            report += f"  Line {event['line']}: {', '.join(event['patterns'])}\n"
            report += f"    → {event['text']}\n"
    else:
        report += "  None detected\n"
    
    report += f"""
SEVERITY SCORE
--------------
Total: {s['severity_score_total']} / {m['total_lines'] * 4}
Risk Level: {"HIGH" if s['severity_score_total'] > m['total_lines'] * 2 else "MEDIUM" if s['severity_score_total'] > m['total_lines'] else "LOW"}

{'='*60}
"""
    return report

def generate_json_report(results):
    """Generate JSON report (machine readable)"""
    return json.dumps(results, indent=2)

def generate_html_report(results):
    """Generate HTML report (browser friendly)"""
    s = results["summary"]
    m = results["metadata"]
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Log Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .critical {{ color: red; font-weight: bold; }}
        .error {{ color: darkred; }}
        .warning {{ color: orange; }}
        .info {{ color: green; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .severity-bar {{ background-color: #4CAF50; height: 20px; }}
    </style>
</head>
<body>
    <h1>Security Log Analysis Report</h1>
    
    <h2>Metadata</h2>
    <p><strong>File:</strong> {m['file']}</p>
    <p><strong>Analyzed:</strong> {m['analyzed_at']}</p>
    <p><strong>Total lines:</strong> {m['total_lines']}</p>
    
    <h2>Severity Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
"""
    for severity, count in s["severity_counts"].items():
        html += f"        <tr><td>{severity}</td><td>{count}</td></tr>\n"
    
    html += f"""
    </table>
    
    <h2>IP Addresses Found ({s['total_ips']})</h2>
    <ul>
"""
    for ip in s["unique_ips"]:
        html += f"        <li>{ip}</li>\n"
    
    html += f"""
    </ul>
    
    <h2>Suspicious Events</h2>
"""
    if s["suspicious_events"]:
        html += "    <ul>\n"
        for event in s["suspicious_events"]:
            html += f"        <li><strong>Line {event['line']}:</strong> {', '.join(event['patterns'])}<br>{event['text']}</li>\n"
        html += "    </ul>\n"
    else:
        html += "    <p>None detected</p>\n"
    
    html += f"""
    <h2>Risk Assessment</h2>
    <p><strong>Severity Score:</strong> {s['severity_score_total']} / {m['total_lines'] * 4}</p>
    <p><strong>Overall Risk Level:</strong> {"HIGH" if s['severity_score_total'] > m['total_lines'] * 2 else "MEDIUM" if s['severity_score_total'] > m['total_lines'] else "LOW"}</p>
    
    <hr>
    <p><em>Generated by Siam's Security Log Analyzer</em></p>
</body>
</html>
"""
    return html

# ============================================================
# MAIN FUNCTION
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Extract IOCs and generate reports",
        epilog="Examples:\n  python3 log_analyzer.py -f sample.log\n  python3 log_analyzer.py -f sample.log -f json -o report.json"
    )
    parser.add_argument("-f", "--file", required=True, help="Path to log file")
    parser.add_argument("-fmt", "--format", choices=["text", "json", "html"], default="text", help="Output format")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    try:
        # Analyze
        results = analyze_log_file(args.file)
        
        # Generate report
        if args.format == "json":
            report = generate_json_report(results)
        elif args.format == "html":
            report = generate_html_report(results)
        else:
            report = generate_text_report(results)
        
        # Output
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"[✓] Report saved to {args.output}")
        else:
            print(report)
            
    except FileNotFoundError as e:
        print(f"[✗] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[✗] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
