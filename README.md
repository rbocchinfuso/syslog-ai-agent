# Syslog Analyzer AI Agent

A comprehensive AI-powered log analysis tool designed to ingest, parse, and analyze **Syslog** and **PRTG Network Monitor** logs. It provides security event detection, anomaly analysis, pattern extraction, and generates actionable daily digests from single files or entire directories.

## Features

### 📥 Multi-Source Ingestion
- **Syslog Support**: Parses BSD, RFC 5424, and ISO standard formats.
- **PRTG Support**: Analyzes PRTG Network Monitor logs (Standard, Value, Alert, and Simple formats).
- **Directory Scanning**: Recursively ingest all log files from a directory with glob pattern filtering.
- **Auto-Detection**: Automatically identifies log types (Syslog vs. PRTG) if not specified.

### 🛡️ Security & Anomaly Detection
- **Security Events**: Detects failed logins, sudo usage, SSH connections, privilege escalation, firewall blocks, brute force attempts, and service attacks.
- **Anomaly Detection**: Identifies message flooding, process spikes, and high error rates.
- **Pattern Extraction**: Automatically extracts IP addresses, usernames, ports, and error codes.

### 📊 Reporting & Digests
- **Human-Readable Reports**: Clear summary of events, severity breakdowns, and top issues.
- **JSON Output**: Machine-readable format for integration with other tools.
- **Daily Digest**: Aggregates data across all ingested files to provide:
  - Unified severity distribution.
  - Hourly activity heatmaps.
  - PRTG device health status (UP/DOWN/WARNING).
  - Smart recommendations based on detected trends.

## Installation

No external dependencies are required. The tool uses only the Python Standard Library.

```bash
# Ensure you have Python 3.6+
python3 --version
```

## Usage

### Command Line Interface

#### Analyze a Single File
```bash
# Auto-detect log type
python3 syslog_analyzer.py /path/to/logfile.log

# Force specific type
python3 syslog_analyzer.py /path/to/syslog --type syslog
python3 syslog_analyzer.py /path/to/prtg.log --type prtg
```

#### Analyze a Directory
```bash
# Analyze all files in a directory
python3 syslog_analyzer.py --directory /var/log/

# Recursive scan (include subdirectories)
python3 syslog_analyzer.py --directory /var/log/ --recursive

# Filter by file extension
python3 syslog_analyzer.py --directory /var/log/ --pattern "*.log"

# Combine directory scan with daily digest
python3 syslog_analyzer.py --directory /var/log/myapp/ --digest
```

#### Output Formats
```bash
# Default human-readable report
python3 syslog_analyzer.py /var/log/syslog

# JSON output for automation
python3 syslog_analyzer.py /var/log/syslog --json

# Detailed Daily Digest
python3 syslog_analyzer.py /var/log/syslog --digest
```

### Python API

You can also use the analyzer as a library in your own Python scripts.

```python
from syslog_analyzer import SyslogAnalyzer

# Initialize
analyzer = SyslogAnalyzer()

# Load from a single file (auto-detect)
analyzer.load_from_file('mixed_logs.txt')

# Load from a directory
analyzer.load_from_directory('/var/log/', recursive=True, pattern='*.log')

# Explicitly load PRTG logs
analyzer.load_prtg_directory('/var/log/prtg/')

# Generate Reports
print(analyzer.get_summary_report())       # Standard summary
print(analyzer.get_daily_digest_report())  # Detailed daily digest

# Get raw JSON data
import json
data = analyzer.get_json_report()
print(json.dumps(data, indent=2))
```

## Log Format Support

### Syslog Formats
The analyzer automatically detects and parses:
- **BSD**: `<Mar 15 10:23:45> hostname process[pid]: message`
- **RFC 5424**: `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`
- **ISO**: `YYYY-MM-DDTHH:MM:SS.sssZ hostname process: message`

### PRTG Formats
Supports common PRTG output styles:
- **Standard**: `[SensorName] Device: X Status: Y message`
- **Value**: `[SensorName] Device: X Value: N Unit Status`
- **Alert**: `Sensor 'X' on Device 'Y' changed to Status`
- **Simple**: `Device Sensor: message`

## Example Output

### Summary Report
```text
=== LOG ANALYSIS SUMMARY ===
Total Entries: 150 (Syslog: 120, PRTG: 30)
Time Range: 2023-10-01 00:00:00 to 2023-10-01 23:59:59

Severity Breakdown:
  CRITICAL: 5
  ERROR:    12
  WARNING:  25
  INFO:     108

Security Events Detected: 8
  - Failed Logins: 3
  - SSH Connections: 5

Top Issues:
  1. [CRITICAL] Possible brute force attack detected from 192.168.1.50
  2. [ERROR] Service nginx failed to start
  3. [WARNING] High memory usage detected
```

### Daily Digest Highlights
```text
=== DAILY DIGEST ===
📅 Date: 2023-10-01

📈 Activity Peak: 14:00 - 15:00 (45 events)

🚨 Critical Trends:
  - 3 Brute force attempts detected from external IPs
  - Service 'nginx' restarted 5 times

🖥️ PRTG Device Health:
  - Healthy: 12 devices
  - Warning: 2 devices (WebServer01, DB-Master)
  - Down: 1 device (Backup-Link)

💡 Recommendations:
  1. Review firewall rules for IP 192.168.1.50
  2. Investigate frequent nginx restarts
  3. Check connectivity for device 'Backup-Link'
```

## License

MIT License. Feel free to modify and distribute.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
