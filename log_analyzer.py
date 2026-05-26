#!/usr/bin/env python3
"""
Security Log Analyzer - Professional Version
Author: Siam Parvez
Date: May 2026
Purpose: Parse security logs, extract IOCs, generate multiple report formats

Usage:
    python3 log_analyzer.py --file sample.log --format json
    python3 log_analyzer.py --file sample.log --format text --output report.txt
    python3 log_analyzer.py --file sample.log --format html --output report.html
    python3 log_analyzer.py --file sample.log --format md --output report.md
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

SEVERITY_KEYWORDS = {
    "CRITICAL": 4,
    "ERROR": 3,
    "WARNING": 2,
    "INFO": 1,
    "DEBUG": 0
}

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
    pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(pattern, text)
    valid_ips = []
    for ip in ips:
        parts = ip.split('.')
        if all(0 <= int(p) <= 255 for p in parts):
            valid_ips.append(ip)
    return list(set(valid_ips))

def get_severity(line):
    line_upper = line.upper()
    for severity, score in SEVERITY_KEYWORDS.items():
        if severity in line_upper:
            return severity, score
    return "UNKNOWN", -1

def detect_suspicious_activity(line):
    detected = []
    line_lower = line.lower()
    for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
        if re.search(pattern, line_lower, re.IGNORECASE):
            detected.append(pattern_name)
    return detected

def parse_log_line(line, line_number):
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
    if not Path(file_path).exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    
    results = {
        "metadata": {
            "file": file_path,
            "analyzed_at": datetime.now().isoformat(),
            "total_lines": len(lines),
            "analyzer_version": "1.0.1"
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
        
        severity = parsed["severity"]
        if severity in results["summary"]["severity_counts"]:
            results["summary"]["severity_counts"][severity] += 1
        
        for ip in parsed["ip_addresses"]:
            all_ips.add(ip)
        
        if parsed["suspicious"]:
            results["summary"]["suspicious_events"].append({
                "line": i,
                "patterns": parsed["suspicious"],
                "text": parsed["raw"][:100]
            })
        
        results["summary"]["severity_score_total"] += parsed["severity_score"]
    
    results["summary"]["unique_ips"] = list(all_ips)
    results["summary"]["total_ips"] = len(all_ips)
    
    return results

# ============================================================
# REPORT GENERATORS
# ============================================================

def generate_text_report(results):
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
"""
    if s['unique_ips']:
        for ip in s['unique_ips']:
            report += f"  • {ip}\n"
    else:
        report += "  None\n"

    report += f"""
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
    return json.dumps(results, indent=2)

def escape_html(text):
    """Escape HTML special characters to prevent XSS in reports"""
    return (text
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#39;')
    )

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
        pre {{ background-color: #f5f5f5; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Security Log Analysis Report</h1>
    
    <h2>Metadata</h2>
    <p><strong>File:</strong> {escape_html(m['file'])}</p>
    <p><strong>Analyzed:</strong> {escape_html(m['analyzed_at'])}</p>
    <p><strong>Total lines:</strong> {m['total_lines']}</p>
    
    <h2>Severity Summary</h2>
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
"""
    for severity, count in s["severity_counts"].items():
        html += f"        <tr><td class='{severity.lower()}'>{escape_html(severity)}</td><td>{count}</td></tr>\n"
    
    html += f"""
    </table>
    
    <h2>IP Addresses Found ({s['total_ips']})</h2>
    <ul>
"""
    for ip in s["unique_ips"]:
        html += f"        <li><code>{escape_html(ip)}</code></li>\n"
    
    html += f"""
    </ul>
    
    <h2>Suspicious Events</h2>
"""
    if s["suspicious_events"]:
        html += "    <ul>\n"
        for event in s["suspicious_events"]:
            html += f"        <li><strong>Line {event['line']}:</strong> {', '.join(event['patterns'])}<br><pre>{escape_html(event['text'])}</pre></li>\n"
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

def generate_markdown_report(results):
    """Generate Markdown report (perfect for GitHub, documentation, bug bounty reports)"""
    s = results["summary"]
    m = results["metadata"]
    
    # Calculate risk level emoji
    risk_score = s['severity_score_total'] / (m['total_lines'] * 4)
    if risk_score > 0.5:
        risk_emoji = "🔴 HIGH"
    elif risk_score > 0.25:
        risk_emoji = "🟡 MEDIUM"
    else:
        risk_emoji = "🟢 LOW"
    
    report = f"""# Security Log Analysis Report

## 📊 Metadata

| Field | Value |
|-------|-------|
| **File** | `{m['file']}` |
| **Analyzed** | `{m['analyzed_at']}` |
| **Total lines** | `{m['total_lines']}` |
| **Analyzer version** | `{m['analyzer_version']}` |

---

## 📈 Severity Summary

| Severity | Count | Chart |
|----------|-------|-------|
"""
    
    for severity in ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]:
        count = s["severity_counts"].get(severity, 0)
        bar = "█" * min(count, 20)
        report += f"| {severity} | {count} | `{bar}` |\n"
    
    report += f"""
---

## 🌐 IP Addresses Found

**Total unique IPs:** `{s['total_ips']}`

"""
    if s['unique_ips']:
        for ip in s['unique_ips']:
            report += f"- `{ip}`\n"
    else:
        report += "> No IP addresses detected\n"
    
    report += f"""

---

## ⚠️ Suspicious Events

**Total events:** `{len(s['suspicious_events'])}`

"""
    if s["suspicious_events"]:
        for event in s["suspicious_events"]:
            report += f"### Line {event['line']}\n"
            report += f"- **Patterns:** `{', '.join(event['patterns'])}`\n"
            report += f"- **Content:**\n"
            report += f"  ```\n  {event['text']}\n  ```\n\n"
    else:
        report += "> No suspicious activity detected\n"
    
    report += f"""

---

## 🎯 Risk Assessment

| Metric | Value |
|--------|-------|
| **Severity Score** | `{s['severity_score_total']} / {m['total_lines'] * 4}` |
| **Risk Level** | {risk_emoji} |

### Score Interpretation

- **0–25%** : 🟢 Low risk – Routine activity
- **25–50%** : 🟡 Medium risk – Requires investigation
- **50%+** : 🔴 High risk – Immediate attention needed

---

## 📋 Raw Data (First 10 lines)

```text
"""
    for detail in results["details"][:10]:
        report += f"{detail['raw']}\n"
    
    report += f"""```

---

*Generated by [Siam's Security Log Analyzer](https://github.com/siam-parvez/security-log-analyzer) on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
    return report

# ============================================================
# MAIN FUNCTION
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Extract IOCs and generate reports",
        epilog="Examples:\n  python3 log_analyzer.py -f sample.log\n  python3 log_analyzer.py -f sample.log -f json -o report.json\n  python3 log_analyzer.py -f sample.log -f md -o report.md"
    )
    parser.add_argument("-f", "--file", required=True, help="Path to log file")
    parser.add_argument("-fmt", "--format", choices=["text", "json", "html", "md"], default="text", help="Output format")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    
    args = parser.parse_args()
    
    try:
        results = analyze_log_file(args.file)
        
        if args.format == "json":
            report = generate_json_report(results)
        elif args.format == "html":
            report = generate_html_report(results)
        elif args.format == "md":
            report = generate_markdown_report(results)
        else:
            report = generate_text_report(results)
        
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
