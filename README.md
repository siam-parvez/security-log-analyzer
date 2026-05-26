# Security Log Analyzer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A professional Python tool for security analysts to parse log files, extract indicators of compromise (IOCs), and generate structured reports in **4 formats**: Text, JSON, HTML, and Markdown.

## Features

| Feature | Description |
|---------|-------------|
| **Severity Classification** | CRITICAL, ERROR, WARNING, INFO, DEBUG |
| **IP Extraction** | Finds and validates IPv4 addresses |
| **Threat Detection** | SQLi, XSS, port scans, command injection |
| **Risk Scoring** | Calculates overall risk level |
| **4 Output Formats** | Text, JSON, HTML, Markdown |

## Installation

```bash
git clone https://github.com/siam-parvez/security-log-analyzer.git
cd security-log-analyzer
```


# No additional dependencies required (uses Python standard library)


## Usage

# Text output (terminal)
python3 log_analyzer.py --file sample.log

# Text output (file)
python3 log_analyzer.py --file sample.log --format text --output report.txt

# JSON output
python3 log_analyzer.py --file sample.log --format json --output report.json

# HTML output
python3 log_analyzer.py --file sample.log --format html --output report.html

# Markdown output
python3 log_analyzer.py --file sample.log --format md --output report.md

# Text output
python3 log_analyzer.py --file sample.log

# JSON output
python3 log_analyzer.py --file sample.log --format json --output report.json

# HTML output
python3 log_analyzer.py --file sample.log --format html --output report.html

# Markdown output
python3 log_analyzer.py --file sample.log --format md --output report.md


## Example Output

### Text Report

```text
============================================================
SECURITY LOG ANALYSIS REPORT
============================================================

SEVERITY SUMMARY
----------------
CRITICAL   :    3 ███
ERROR      :    6 ██████
WARNING    :    5 █████
INFO       :    7 ███████

IP ADDRESSES FOUND
-----------------
  • 192.168.1.100
  • 203.0.113.45
  • 45.33.22.11

SUSPICIOUS EVENTS
-----------------
  Line 9: command_injection
    → Suspicious command detected: cat /etc/passwd

  Line 18: sql_injection
    → IDS Alert - Possible SQL Injection Attack
```

---

## Sample Log Format

The tool accepts standard log files.

Example:

```text
2026-05-26 08:17:45 ERROR Failed login attempt from 203.0.113.45
```

---

## Use Cases

- 🔐 **SOC Analysts** — Quickly triage firewall, IDS, and authentication logs
- 🐞 **Bug Bounty Hunters** — Parse target application logs for suspicious activity
- 📋 **Incident Response Teams** — Extract IOCs and identify attack patterns
- 📊 **Compliance & Auditing** — Generate audit-ready security summaries
- 🛡️ **Blue Teams** — Detect brute force attempts, injections, and anomalies
- ⚡ **DevSecOps Engineers** — Automate security monitoring in CI/CD pipelines
