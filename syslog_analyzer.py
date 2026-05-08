#!/usr/bin/env python3
"""
Syslog Analyzer AI Agent
Analyzes syslog data (including PRTG logs) to detect patterns, anomalies, and security issues.
Provides daily digest summaries with aggregated insights.
"""

import re
import json
import os
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum


class SeverityLevel(Enum):
    """Syslog severity levels based on RFC 5424."""
    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


@dataclass
class SyslogEntry:
    """Represents a parsed syslog entry."""
    timestamp: Optional[datetime]
    hostname: str
    facility: str
    severity: SeverityLevel
    process: str
    pid: Optional[int]
    message: str
    raw_line: str
    log_source: str = "syslog"  # 'syslog' or 'prtg'
    prtg_sensor: Optional[str] = None
    prtg_device: Optional[str] = None
    prtg_status: Optional[str] = None
    prtg_value: Optional[float] = None
    
    def to_dict(self) -> dict:
        return {
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'hostname': self.hostname,
            'facility': self.facility,
            'severity': self.severity.name,
            'process': self.process,
            'pid': self.pid,
            'message': self.message,
            'raw_line': self.raw_line,
            'log_source': self.log_source,
            'prtg_sensor': self.prtg_sensor,
            'prtg_device': self.prtg_device,
            'prtg_status': self.prtg_status,
            'prtg_value': self.prtg_value
        }


@dataclass
class AnalysisResult:
    """Contains the results of syslog analysis."""
    total_entries: int
    time_range: Tuple[Optional[datetime], Optional[datetime]]
    severity_distribution: Dict[str, int]
    top_processes: List[Tuple[str, int]]
    top_hosts: List[Tuple[str, int]]
    error_messages: List[str]
    security_events: List[Dict]
    anomalies: List[Dict]
    patterns: Dict[str, List[str]]
    prtg_summary: Optional[Dict] = None  # PRTG-specific summary
    daily_digest: Optional[Dict] = None  # Daily digest data
    
    def to_dict(self) -> dict:
        result = asdict(self)
        result['time_range'] = [
            self.time_range[0].isoformat() if self.time_range[0] else None,
            self.time_range[1].isoformat() if self.time_range[1] else None
        ]
        return result


@dataclass
class DailyDigest:
    """Represents a daily digest summary."""
    date: str
    total_entries: int
    syslog_entries: int
    prtg_entries: int
    severity_breakdown: Dict[str, int]
    top_issues: List[str]
    security_events_count: int
    anomaly_count: int
    prtg_device_status: Dict[str, str]
    prtg_sensor_alerts: List[str]
    hourly_distribution: Dict[int, int]
    recommendations: List[str]
    
    def to_dict(self) -> dict:
        return asdict(self)


class SyslogParser:
    """Parses syslog entries from various formats."""
    
    # Common syslog patterns
    PATTERNS = [
        # BSD syslog: "Mon DD HH:MM:SS hostname process[pid]: message"
        re.compile(
            r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>[\w\-\.]+)\s+'
            r'(?P<process>[\w\-\.]+)(?:\[(?P<pid>\d+)\])?:\s*'
            r'(?P<message>.*)$'
        ),
        # RFC 5424: "<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG"
        re.compile(
            r'^<(?P<pri>\d+)>(?P<version>\d+)\s+'
            r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[\+\-]\d{2}:?\d{2})?)\s+'
            r'(?P<hostname>[\w\-\.]+)\s+'
            r'(?P<process>[\w\-\.]+)\s+'
            r'(?P<pid>\d+|-)\s+'
            r'(?P<msgid>\S+)\s+'
            r'(?P<message>.*)$'
        ),
        # ISO format: "YYYY-MM-DDTHH:MM:SS hostname process[pid]: message"
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
            r'(?P<hostname>[\w\-\.]+)\s+'
            r'(?P<process>[\w\-\.]+)(?:\[(?P<pid>\d+)\])?:\s*'
            r'(?P<message>.*)$'
        ),
    ]
    
    FACILITY_MAP = {
        0: 'kern', 1: 'user', 2: 'mail', 3: 'daemon',
        4: 'auth', 5: 'syslog', 6: 'lpr', 7: 'news',
        8: 'uucp', 9: 'cron', 10: 'authpriv', 11: 'ftp',
        16: 'local0', 17: 'local1', 18: 'local2', 19: 'local3',
        20: 'local4', 21: 'local5', 22: 'local6', 23: 'local7'
    }
    
    def parse_priority(self, pri: int) -> Tuple[str, SeverityLevel]:
        """Extract facility and severity from priority value."""
        facility_num = pri >> 3
        severity_num = pri & 0x07
        facility = self.FACILITY_MAP.get(facility_num, f'facility{facility_num}')
        severity = SeverityLevel(severity_num)
        return facility, severity
    
    def parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse timestamp from various formats."""
        formats = [
            '%b %d %H:%M:%S',  # BSD format
            '%Y-%m-%dT%H:%M:%S',  # ISO format without timezone
            '%Y-%m-%dT%H:%M:%S.%f',  # ISO format with microseconds
            '%Y-%m-%dT%H:%M:%SZ',  # ISO format with Z
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(ts_str, fmt)
                # For BSD format without year, assume current year
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
        
        # Try with timezone offset
        try:
            ts_clean = re.sub(r'[+-]\d{2}:?\d{2}$', '', ts_str)
            ts_clean = ts_clean.rstrip('Z')
            return datetime.fromisoformat(ts_clean)
        except:
            pass
        
        return None
    
    def parse_line(self, line: str) -> Optional[SyslogEntry]:
        """Parse a single syslog line."""
        line = line.strip()
        if not line:
            return None
        
        for pattern in self.PATTERNS:
            match = pattern.match(line)
            if match:
                groups = match.groupdict()
                
                # Handle RFC 5424 priority
                if 'pri' in groups:
                    facility, severity = self.parse_priority(int(groups['pri']))
                else:
                    facility = 'user'
                    severity = SeverityLevel.INFORMATIONAL
                
                # Parse timestamp
                timestamp = self.parse_timestamp(groups['timestamp'])
                
                # Parse PID
                pid = None
                if groups.get('pid') and groups['pid'] != '-':
                    try:
                        pid = int(groups['pid'])
                    except ValueError:
                        pass
                
                return SyslogEntry(
                    timestamp=timestamp,
                    hostname=groups.get('hostname', 'unknown'),
                    facility=facility,
                    severity=severity,
                    process=groups.get('process', 'unknown'),
                    pid=pid,
                    message=groups.get('message', ''),
                    raw_line=line
                )
        
        # If no pattern matches, create a basic entry
        return SyslogEntry(
            timestamp=None,
            hostname='unknown',
            facility='user',
            severity=SeverityLevel.INFORMATIONAL,
            process='unknown',
            pid=None,
            message=line,
            raw_line=line
        )


class PRTGLogParser:
    """Parses PRTG Network Monitor log entries."""
    
    # PRTG log patterns
    PATTERNS = [
        # PRTG standard format: "YYYY-MM-DD HH:MM:SS [SensorName] Device: DeviceName Status: Status Message"
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'\[(?P<sensor>[^\]]+)\]\s+'
            r'Device:\s*(?P<device>[^\n]+?)\s+'
            r'Status:\s*(?P<status>\w+)\s*'
            r'(?P<message>.*)$'
        ),
        # PRTG with value: "YYYY-MM-DD HH:MM:SS [SensorName] Device: DeviceName Value: X Unit Status"
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'\[(?P<sensor>[^\]]+)\]\s+'
            r'Device:\s*(?P<device>[^\n]+?)\s+'
            r'Value:\s*(?P<value>[\d\.]+)\s*'
            r'(?P<unit>\w+)?\s*'
            r'(?P<status>\w+)?\s*'
            r'(?P<message>.*)$'
        ),
        # PRTG alert format: "YYYY-MM-DD HH:MM:SS - Sensor 'SensorName' on Device 'DeviceName' changed to Status"
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+-\s+'
            r'Sensor\s+[\'\"](?P<sensor>[^\'\"]+)[\'\"]\s+on\s+Device\s+'
            r'[\'\"](?P<device>[^\'\"]+)[\'\"]\s+'
            r'changed to\s+(?P<status>\w+)'
            r'(?:\s+-\s+(?P<message>.*))?$'
        ),
        # PRTG simple format: "YYYY-MM-DD HH:MM:SS Device Sensor: message"
        re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<device>[\w\-\.]+)\s+'
            r'(?P<sensor>[\w\-\.]+):\s*'
            r'(?P<message>.*)$'
        ),
    ]
    
    STATUS_SEVERITY_MAP = {
        'up': SeverityLevel.INFORMATIONAL,
        'ok': SeverityLevel.INFORMATIONAL,
        'warning': SeverityLevel.WARNING,
        'down': SeverityLevel.CRITICAL,
        'error': SeverityLevel.ERROR,
        'critical': SeverityLevel.CRITICAL,
        'timeout': SeverityLevel.WARNING,
        'unknown': SeverityLevel.NOTICE,
    }
    
    def parse_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse PRTG timestamp."""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        return None
    
    def extract_value(self, message: str) -> Optional[float]:
        """Extract numeric value from message."""
        match = re.search(r'(\d+\.?\d*)\s*(?:%|bps|B|KB|MB|GB|ms|s)?', message)
        if match:
            try:
                return float(match.group(1))
            except ValueError:
                pass
        return None
    
    def parse_line(self, line: str) -> Optional[SyslogEntry]:
        """Parse a single PRTG log line."""
        line = line.strip()
        if not line:
            return None
        
        # Check if it looks like a PRTG log
        if not any(indicator in line.lower() for indicator in 
                   ['prtg', 'sensor', 'device:', 'status:', 'changed to']):
            return None
        
        for pattern in self.PATTERNS:
            match = pattern.match(line)
            if match:
                groups = match.groupdict()
                
                timestamp = self.parse_timestamp(groups['timestamp'])
                sensor = groups.get('sensor', 'unknown')
                device = groups.get('device', 'unknown')
                status = groups.get('status', 'unknown').lower()
                message = groups.get('message', '')
                
                # Determine severity from status
                severity = self.STATUS_SEVERITY_MAP.get(status, SeverityLevel.INFORMATIONAL)
                
                # Extract numeric value if present
                prtg_value = groups.get('value')
                if prtg_value:
                    try:
                        prtg_value = float(prtg_value)
                    except ValueError:
                        prtg_value = self.extract_value(message)
                else:
                    prtg_value = self.extract_value(message)
                
                return SyslogEntry(
                    timestamp=timestamp,
                    hostname=device,
                    facility='prtg',
                    severity=severity,
                    process=sensor,
                    pid=None,
                    message=message or f"Status: {status}",
                    raw_line=line,
                    log_source='prtg',
                    prtg_sensor=sensor,
                    prtg_device=device,
                    prtg_status=status,
                    prtg_value=prtg_value
                )
        
        # Fallback: Try to extract basic PRTG info from unstructured line
        if 'sensor' in line.lower() or 'prtg' in line.lower():
            timestamp = self.extract_value(line)  # This won't work, but we'll set None
            return SyslogEntry(
                timestamp=None,
                hostname='unknown',
                facility='prtg',
                severity=SeverityLevel.INFORMATIONAL,
                process='prtg',
                pid=None,
                message=line,
                raw_line=line,
                log_source='prtg'
            )
        
        return None


class SecurityEventDetector:
    """Detects security-related events in syslog entries."""
    
    SECURITY_PATTERNS = {
        'failed_login': [
            r'failed\s+(password|login)',
            r'authentication\s+fail',
            r'invalid\s+user',
            r'failed\s+publickey',
        ],
        'successful_login': [
            r'(accepted|successful)\s+(password|publickey|login)',
            r'session\s+opened',
        ],
        'sudo_usage': [
            r'sudo:',
            r'sudo\[',
        ],
        'ssh_connection': [
            r'sshd.*(?:connect|disconnect|connection)',
        ],
        'privilege_escalation': [
            r'privilege.*escalat',
            r'su:\s*session\s+opened.*root',
            r'became\s+root',
        ],
        'firewall_block': [
            r'(iptables|ufw|firewalld).*(?:DROP|REJECT|BLOCK)',
            r'blocked',
        ],
        'brute_force': [
            r'repeated\s+login\s+failures',
            r'too\s+many\s+authentication\s+failures',
        ],
        'service_attack': [
            r'DDOS',
            r'flood',
            r'(attack|exploit|injection)',
        ]
    }
    
    def __init__(self):
        self.compiled_patterns = {}
        for event_type, patterns in self.SECURITY_PATTERNS.items():
            self.compiled_patterns[event_type] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def detect(self, entry: SyslogEntry) -> List[Dict]:
        """Detect security events in a syslog entry."""
        events = []
        text_to_search = f"{entry.process} {entry.message}"
        
        for event_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(text_to_search):
                    events.append({
                        'type': event_type,
                        'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                        'hostname': entry.hostname,
                        'process': entry.process,
                        'message': entry.message[:200],
                        'severity': entry.severity.name
                    })
                    break  # Only report once per event type per entry
        
        return events


class AnomalyDetector:
    """Detects anomalies in syslog patterns."""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.message_counts = Counter()
        self.process_counts = Counter()
        self.error_rates = defaultdict(list)
        self.baseline_established = False
    
    def analyze_batch(self, entries: List[SyslogEntry]) -> List[Dict]:
        """Analyze a batch of entries for anomalies."""
        anomalies = []
        
        # Count messages and processes
        for entry in entries:
            self.message_counts[entry.message[:50]] += 1
            self.process_counts[entry.process] += 1
            
            if entry.severity.value <= SeverityLevel.ERROR.value:
                self.error_rates[entry.process].append(entry.timestamp)
        
        # Detect message flooding
        for msg, count in self.message_counts.items():
            if count > self.window_size * 0.5:  # Same message > 50% of window
                anomalies.append({
                    'type': 'message_flood',
                    'description': f'Repeated message detected: {msg}',
                    'count': count,
                    'threshold': self.window_size * 0.5
                })
        
        # Detect process spike
        total = sum(self.process_counts.values())
        for proc, count in self.process_counts.items():
            if total > 10 and count / total > 0.3:  # Process > 30% of all logs
                anomalies.append({
                    'type': 'process_spike',
                    'description': f'Unusual activity from process: {proc}',
                    'count': count,
                    'percentage': round(count / total * 100, 2)
                })
        
        # Detect error rate spike
        for proc, timestamps in self.error_rates.items():
            if len(timestamps) > self.window_size * 0.2:  # > 20% errors
                anomalies.append({
                    'type': 'high_error_rate',
                    'description': f'High error rate for process: {proc}',
                    'error_count': len(timestamps),
                    'threshold': self.window_size * 0.2
                })
        
        return anomalies


class PatternExtractor:
    """Extracts common patterns from syslog messages."""
    
    def extract_patterns(self, entries: List[SyslogEntry]) -> Dict[str, List[str]]:
        """Extract and categorize patterns from messages."""
        patterns = defaultdict(list)
        
        # IP addresses
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        # Users
        user_pattern = re.compile(r'\buser[=:\s]+(\w+)', re.IGNORECASE)
        # Ports
        port_pattern = re.compile(r'\bport[=:\s]+(\d+)', re.IGNORECASE)
        # Error codes
        error_code_pattern = re.compile(r'\b(error|errno|exit)[=:\s]*(\d+)', re.IGNORECASE)
        
        for entry in entries:
            message = entry.message
            
            ips = ip_pattern.findall(message)
            if ips:
                patterns['ip_addresses'].extend(ips)
            
            users = user_pattern.findall(message)
            if users:
                patterns['users'].extend(users)
            
            ports = port_pattern.findall(message)
            if ports:
                patterns['ports'].extend(ports)
            
            errors = error_code_pattern.findall(message)
            if errors:
                patterns['error_codes'].extend([f"{e[0]}:{e[1]}" for e in errors])
        
        # Deduplicate and limit
        for key in patterns:
            patterns[key] = list(set(patterns[key]))[:100]
        
        return dict(patterns)


class SyslogAnalyzer:
    """Main AI agent for analyzing syslog data."""
    
    def __init__(self):
        self.parser = SyslogParser()
        self.prtg_parser = PRTGLogParser()
        self.security_detector = SecurityEventDetector()
        self.anomaly_detector = AnomalyDetector()
        self.pattern_extractor = PatternExtractor()
        self.entries: List[SyslogEntry] = []
    
    def load_from_file(self, filepath: str, log_type: str = 'auto') -> int:
        """Load syslog or PRTG data from a file.
        
        Args:
            filepath: Path to the log file
            log_type: 'syslog', 'prtg', or 'auto' (default: auto-detect)
        """
        count = 0
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                entry = None
                if log_type == 'prtg':
                    entry = self.prtg_parser.parse_line(line)
                elif log_type == 'syslog':
                    entry = self.parser.parse_line(line)
                else:  # auto-detect
                    # Try PRTG first if it looks like PRTG
                    if any(indicator in line.lower() for indicator in 
                           ['prtg', 'sensor', 'device:', 'status:', 'changed to']):
                        entry = self.prtg_parser.parse_line(line)
                    if not entry:
                        entry = self.parser.parse_line(line)
                
                if entry:
                    self.entries.append(entry)
                    count += 1
        return count
    
    def load_from_string(self, text: str, log_type: str = 'auto') -> int:
        """Load syslog or PRTG data from a string.
        
        Args:
            text: Log content as string
            log_type: 'syslog', 'prtg', or 'auto' (default: auto-detect)
        """
        count = 0
        for line in text.split('\n'):
            entry = None
            if log_type == 'prtg':
                entry = self.prtg_parser.parse_line(line)
            elif log_type == 'syslog':
                entry = self.parser.parse_line(line)
            else:  # auto-detect
                if any(indicator in line.lower() for indicator in 
                       ['prtg', 'sensor', 'device:', 'status:', 'changed to']):
                    entry = self.prtg_parser.parse_line(line)
                if not entry:
                    entry = self.parser.parse_line(line)
            
            if entry:
                self.entries.append(entry)
                count += 1
        return count
    
    def load_prtg_file(self, filepath: str) -> int:
        """Load PRTG log data from a file."""
        return self.load_from_file(filepath, log_type='prtg')
    
    def load_syslog_file(self, filepath: str) -> int:
        """Load syslog data from a file."""
        return self.load_from_file(filepath, log_type='syslog')
    
    def load_from_directory(self, directory: str, log_type: str = 'auto', 
                            recursive: bool = False, pattern: str = None) -> int:
        """Load syslog or PRTG data from all files in a directory.
        
        Args:
            directory: Path to the directory containing log files
            log_type: 'syslog', 'prtg', or 'auto' (default: auto-detect per file)
            recursive: If True, recursively search subdirectories (default: False)
            pattern: Optional glob pattern to filter files (e.g., '*.log', 'syslog*')
        
        Returns:
            Total number of entries loaded from all files
        """
        dir_path = Path(directory)
        if not dir_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        if not dir_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")
        
        total_count = 0
        
        # Determine glob pattern
        if pattern:
            glob_pattern = pattern
        else:
            # Default patterns for common log files
            glob_pattern = '*'
        
        # Get all matching files
        if recursive:
            files = dir_path.rglob(glob_pattern)
        else:
            files = dir_path.glob(glob_pattern)
        
        # Filter to only files (not directories)
        for file_path in files:
            if file_path.is_file():
                try:
                    count = self.load_from_file(str(file_path), log_type)
                    if count > 0:
                        print(f"Loaded {count} entries from {file_path}")
                        total_count += count
                except Exception as e:
                    print(f"Warning: Could not load {file_path}: {e}")
        
        return total_count
    
    def load_syslog_directory(self, directory: str, recursive: bool = False, 
                              pattern: str = None) -> int:
        """Load syslog data from all files in a directory.
        
        Convenience method that calls load_from_directory with log_type='syslog'.
        """
        return self.load_from_directory(directory, log_type='syslog', 
                                        recursive=recursive, pattern=pattern)
    
    def load_prtg_directory(self, directory: str, recursive: bool = False,
                            pattern: str = None) -> int:
        """Load PRTG data from all files in a directory.
        
        Convenience method that calls load_from_directory with log_type='prtg'.
        """
        return self.load_from_directory(directory, log_type='prtg',
                                        recursive=recursive, pattern=pattern)
    
    def analyze(self) -> AnalysisResult:
        """Perform comprehensive analysis on loaded syslog data."""
        if not self.entries:
            return AnalysisResult(
                total_entries=0,
                time_range=(None, None),
                severity_distribution={},
                top_processes=[],
                top_hosts=[],
                error_messages=[],
                security_events=[],
                anomalies=[],
                patterns={},
                prtg_summary=None,
                daily_digest=None
            )
        
        # Calculate time range
        timestamps = [e.timestamp for e in self.entries if e.timestamp]
        time_range = (min(timestamps) if timestamps else None, 
                      max(timestamps) if timestamps else None)
        
        # Severity distribution
        severity_dist = Counter(e.severity.name for e in self.entries)
        
        # Top processes
        process_counts = Counter(e.process for e in self.entries)
        top_processes = process_counts.most_common(10)
        
        # Top hosts
        host_counts = Counter(e.hostname for e in self.entries)
        top_hosts = host_counts.most_common(10)
        
        # Error messages
        error_messages = [
            e.message for e in self.entries 
            if e.severity.value <= SeverityLevel.ERROR.value
        ][:50]
        
        # Security events
        security_events = []
        for entry in self.entries:
            events = self.security_detector.detect(entry)
            security_events.extend(events)
        
        # Anomalies
        anomalies = self.anomaly_detector.analyze_batch(self.entries)
        
        # Patterns
        patterns = self.pattern_extractor.extract_patterns(self.entries)
        
        # PRTG Summary
        prtg_summary = self._generate_prtg_summary()
        
        # Daily Digest
        daily_digest = self._generate_daily_digest()
        
        return AnalysisResult(
            total_entries=len(self.entries),
            time_range=time_range,
            severity_distribution=dict(severity_dist),
            top_processes=top_processes,
            top_hosts=top_hosts,
            error_messages=error_messages,
            security_events=security_events[:100],  # Limit to 100
            anomalies=anomalies,
            patterns=patterns,
            prtg_summary=prtg_summary,
            daily_digest=daily_digest.to_dict() if daily_digest else None
        )
    
    def _generate_prtg_summary(self) -> Optional[Dict]:
        """Generate PRTG-specific summary statistics."""
        prtg_entries = [e for e in self.entries if e.log_source == 'prtg']
        
        if not prtg_entries:
            return None
        
        # Device status summary
        device_status = defaultdict(lambda: {'up': 0, 'down': 0, 'warning': 0, 'other': 0})
        sensor_alerts = []
        values_by_sensor = defaultdict(list)
        
        for entry in prtg_entries:
            device = entry.prtg_device or entry.hostname
            status = entry.prtg_status or 'unknown'
            
            if status in ['up', 'ok']:
                device_status[device]['up'] += 1
            elif status in ['down', 'critical', 'error']:
                device_status[device]['down'] += 1
                if entry.message:
                    sensor_alerts.append(f"{entry.prtg_sensor} on {device}: {entry.message}")
            elif status in ['warning', 'timeout']:
                device_status[device]['warning'] += 1
                if entry.message:
                    sensor_alerts.append(f"{entry.prtg_sensor} on {device}: {entry.message}")
            else:
                device_status[device]['other'] += 1
            
            if entry.prtg_value is not None:
                values_by_sensor[entry.prtg_sensor].append(entry.prtg_value)
        
        # Calculate averages for sensors with values
        sensor_averages = {}
        for sensor, values in values_by_sensor.items():
            if values:
                sensor_averages[sensor] = {
                    'avg': round(sum(values) / len(values), 2),
                    'min': round(min(values), 2),
                    'max': round(max(values), 2),
                    'count': len(values)
                }
        
        # Determine overall device health
        device_health = {}
        for device, statuses in device_status.items():
            if statuses['down'] > 0:
                device_health[device] = 'DOWN'
            elif statuses['warning'] > 0:
                device_health[device] = 'WARNING'
            else:
                device_health[device] = 'HEALTHY'
        
        return {
            'total_prtg_entries': len(prtg_entries),
            'unique_devices': len(device_status),
            'unique_sensors': len(values_by_sensor),
            'device_health': device_health,
            'sensor_alerts': sensor_alerts[:50],  # Limit alerts
            'sensor_metrics': sensor_averages,
            'status_distribution': {
                'up': sum(s['up'] for s in device_status.values()),
                'down': sum(s['down'] for s in device_status.values()),
                'warning': sum(s['warning'] for s in device_status.values()),
                'other': sum(s['other'] for s in device_status.values())
            }
        }
    
    def _generate_daily_digest(self) -> Optional[DailyDigest]:
        """Generate a daily digest summary of all log data."""
        if not self.entries:
            return None
        
        # Group entries by date
        entries_by_date = defaultdict(list)
        for entry in self.entries:
            if entry.timestamp:
                date_key = entry.timestamp.strftime('%Y-%m-%d')
                entries_by_date[date_key].append(entry)
        
        # Use the most recent date with data, or today if no timestamps
        if entries_by_date:
            digest_date = max(entries_by_date.keys())
            day_entries = entries_by_date[digest_date]
        else:
            digest_date = datetime.now().strftime('%Y-%m-%d')
            day_entries = self.entries
        
        # Count by source
        syslog_count = sum(1 for e in day_entries if e.log_source == 'syslog')
        prtg_count = sum(1 for e in day_entries if e.log_source == 'prtg')
        
        # Severity breakdown
        severity_breakdown = dict(Counter(e.severity.name for e in day_entries))
        
        # Top issues (errors and critical events)
        top_issues = []
        for entry in day_entries:
            if entry.severity.value <= SeverityLevel.ERROR.value:
                issue = f"[{entry.severity.name}] {entry.process}: {entry.message[:100]}"
                top_issues.append(issue)
        top_issues = top_issues[:10]
        
        # Security events count
        security_events_count = 0
        for entry in day_entries:
            events = self.security_detector.detect(entry)
            security_events_count += len(events)
        
        # Anomaly count (simplified)
        anomaly_count = sum(1 for e in day_entries if e.severity.value <= SeverityLevel.WARNING.value)
        
        # PRTG device status
        prtg_device_status = {}
        prtg_sensor_alerts = []
        for entry in day_entries:
            if entry.log_source == 'prtg':
                device = entry.prtg_device or entry.hostname
                status = entry.prtg_status or 'unknown'
                if status in ['down', 'critical', 'error', 'warning']:
                    prtg_device_status[device] = status.upper()
                    if entry.message:
                        prtg_sensor_alerts.append(f"{entry.prtg_sensor}: {entry.message}")
        
        # Hourly distribution
        hourly_dist = defaultdict(int)
        for entry in day_entries:
            if entry.timestamp:
                hourly_dist[entry.timestamp.hour] += 1
        
        # Generate recommendations
        recommendations = []
        if security_events_count > 5:
            recommendations.append(f"Review {security_events_count} security events detected")
        if prtg_count > 0 and any(s in ['DOWN', 'CRITICAL'] for s in prtg_device_status.values()):
            recommendations.append("Critical PRTG device issues require immediate attention")
        if severity_breakdown.get('CRITICAL', 0) > 0:
            recommendations.append(f"Investigate {severity_breakdown.get('CRITICAL', 0)} critical system events")
        if severity_breakdown.get('ERROR', 0) > 10:
            recommendations.append("High error rate detected - review system health")
        if not recommendations:
            recommendations.append("No critical issues detected - continue regular monitoring")
        
        return DailyDigest(
            date=digest_date,
            total_entries=len(day_entries),
            syslog_entries=syslog_count,
            prtg_entries=prtg_count,
            severity_breakdown=severity_breakdown,
            top_issues=top_issues,
            security_events_count=security_events_count,
            anomaly_count=anomaly_count,
            prtg_device_status=prtg_device_status,
            prtg_sensor_alerts=list(set(prtg_sensor_alerts))[:20],
            hourly_distribution=dict(hourly_dist),
            recommendations=recommendations
        )
    
    def get_summary_report(self) -> str:
        """Generate a human-readable summary report."""
        result = self.analyze()
        
        report = []
        report.append("=" * 60)
        report.append("SYSLOG ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"\nTotal Entries Analyzed: {result.total_entries}")
        
        if result.time_range[0] and result.time_range[1]:
            report.append(f"Time Range: {result.time_range[0]} to {result.time_range[1]}")
        
        report.append("\n--- SEVERITY DISTRIBUTION ---")
        for severity, count in sorted(result.severity_distribution.items()):
            report.append(f"  {severity}: {count}")
        
        report.append("\n--- TOP PROCESSES ---")
        for process, count in result.top_processes[:5]:
            report.append(f"  {process}: {count} entries")
        
        report.append("\n--- TOP HOSTS ---")
        for host, count in result.top_hosts[:5]:
            report.append(f"  {host}: {count} entries")
        
        if result.security_events:
            report.append(f"\n--- SECURITY EVENTS ({len(result.security_events)} detected) ---")
            event_types = Counter(e['type'] for e in result.security_events)
            for event_type, count in event_types.most_common(5):
                report.append(f"  {event_type}: {count}")
        
        if result.anomalies:
            report.append(f"\n--- ANOMALIES ({len(result.anomalies)} detected) ---")
            for anomaly in result.anomalies[:5]:
                report.append(f"  [{anomaly['type']}] {anomaly['description']}")
        
        if result.patterns:
            report.append("\n--- EXTRACTED PATTERNS ---")
            for pattern_type, values in result.patterns.items():
                if values:
                    report.append(f"  {pattern_type}: {len(values)} unique values")
        
        # PRTG Summary
        if result.prtg_summary:
            report.append("\n--- PRTG SUMMARY ---")
            report.append(f"  Total PRTG Entries: {result.prtg_summary.get('total_prtg_entries', 0)}")
            report.append(f"  Unique Devices: {result.prtg_summary.get('unique_devices', 0)}")
            report.append(f"  Unique Sensors: {result.prtg_summary.get('unique_sensors', 0)}")
            
            status_dist = result.prtg_summary.get('status_distribution', {})
            report.append(f"  Status Distribution:")
            report.append(f"    UP: {status_dist.get('up', 0)}")
            report.append(f"    DOWN: {status_dist.get('down', 0)}")
            report.append(f"    WARNING: {status_dist.get('warning', 0)}")
            
            device_health = result.prtg_summary.get('device_health', {})
            issues = [f"{d}: {s}" for d, s in device_health.items() if s != 'HEALTHY']
            if issues:
                report.append(f"  Device Issues:")
                for issue in issues[:5]:
                    report.append(f"    - {issue}")
        
        # Daily Digest
        if result.daily_digest:
            report.append("\n--- DAILY DIGEST ---")
            dd = result.daily_digest
            report.append(f"  Date: {dd.get('date', 'N/A')}")
            report.append(f"  Syslog Entries: {dd.get('syslog_entries', 0)}")
            report.append(f"  PRTG Entries: {dd.get('prtg_entries', 0)}")
            report.append(f"  Security Events: {dd.get('security_events_count', 0)}")
            
            recommendations = dd.get('recommendations', [])
            if recommendations:
                report.append(f"  Recommendations:")
                for rec in recommendations[:5]:
                    report.append(f"    - {rec}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)
    
    def get_daily_digest_report(self) -> str:
        """Generate a dedicated daily digest report."""
        result = self.analyze()
        
        if not result.daily_digest:
            return "No data available for daily digest."
        
        dd = result.daily_digest
        
        report = []
        report.append("=" * 60)
        report.append("DAILY LOG DIGEST")
        report.append("=" * 60)
        report.append(f"\nDate: {dd['date']}")
        report.append(f"\nOVERVIEW")
        report.append(f"  Total Log Entries: {dd['total_entries']}")
        report.append(f"  - Syslog: {dd['syslog_entries']}")
        report.append(f"  - PRTG: {dd['prtg_entries']}")
        
        report.append(f"\nSEVERITY BREAKDOWN")
        for severity, count in sorted(dd['severity_breakdown'].items(), key=lambda x: x[1], reverse=True):
            report.append(f"  {severity}: {count}")
        
        if dd['top_issues']:
            report.append(f"\nTOP ISSUES")
            for i, issue in enumerate(dd['top_issues'], 1):
                report.append(f"  {i}. {issue}")
        
        report.append(f"\nSECURITY & ANOMALIES")
        report.append(f"  Security Events: {dd['security_events_count']}")
        report.append(f"  Potential Anomalies: {dd['anomaly_count']}")
        
        if dd['prtg_device_status']:
            report.append(f"\nPRTG DEVICE STATUS")
            for device, status in dd['prtg_device_status'].items():
                report.append(f"  {device}: {status}")
        
        if dd['prtg_sensor_alerts']:
            report.append(f"\nPRTG SENSOR ALERTS")
            for alert in dd['prtg_sensor_alerts'][:10]:
                report.append(f"  - {alert}")
        
        if dd['hourly_distribution']:
            report.append(f"\nHOURLY DISTRIBUTION")
            for hour in sorted(dd['hourly_distribution'].keys()):
                count = dd['hourly_distribution'][hour]
                bar = "█" * min(count, 50)
                report.append(f"  {hour:02d}:00 | {bar} ({count})")
        
        report.append(f"\nRECOMMENDATIONS")
        for i, rec in enumerate(dd['recommendations'], 1):
            report.append(f"  {i}. {rec}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)


def main():
    """Example usage of the Syslog Analyzer."""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Syslog Analyzer AI Agent - Analyze syslog and PRTG logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single file
  python3 syslog_analyzer.py /var/log/syslog
  
  # Analyze all files in a directory
  python3 syslog_analyzer.py --directory /var/log/
  
  # Analyze only *.log files in a directory
  python3 syslog_analyzer.py --directory /var/log/ --pattern "*.log"
  
  # Recursively analyze all subdirectories
  python3 syslog_analyzer.py --directory /var/log/ --recursive
  
  # Analyze PRTG logs specifically
  python3 syslog_analyzer.py /path/to/prtg.log prtg
  
  # Show daily digest report
  python3 syslog_analyzer.py /var/log/syslog --digest
  
  # Analyze directory and show daily digest
  python3 syslog_analyzer.py --directory /var/log/ --digest
        """
    )
    
    parser.add_argument('file', nargs='?', help='Single log file to analyze')
    parser.add_argument('--directory', '-d', help='Directory containing log files to analyze')
    parser.add_argument('--recursive', '-r', action='store_true', 
                        help='Recursively search subdirectories (only with --directory)')
    parser.add_argument('--pattern', '-p', default=None,
                        help='Glob pattern to filter files (e.g., "*.log", "syslog*")')
    parser.add_argument('log_type', nargs='?', default='auto',
                        choices=['auto', 'syslog', 'prtg'],
                        help='Log type: auto-detect, syslog, or prtg (default: auto)')
    parser.add_argument('--digest', action='store_true',
                        help='Show detailed daily digest report')
    parser.add_argument('--json', action='store_true',
                        help='Output results in JSON format')
    
    args = parser.parse_args()
    
    analyzer = SyslogAnalyzer()
    
    # Determine what to load
    if args.directory:
        # Load from directory
        print(f"Loading logs from directory: {args.directory}")
        if args.recursive:
            print(f"  (recursive search enabled)")
        if args.pattern:
            print(f"  (filtering by pattern: {args.pattern})")
        
        count = analyzer.load_from_directory(
            args.directory,
            log_type=args.log_type,
            recursive=args.recursive,
            pattern=args.pattern
        )
        print(f"\nTotal: Loaded {count} log entries from directory")
    elif args.file:
        # Load from single file
        count = analyzer.load_from_file(args.file, log_type=args.log_type)
        print(f"Loaded {count} log entries from {args.file}")
    else:
        # Demo with sample data including PRTG logs
        current_year = datetime.now().year
        sample_logs = f"""
Jan 15 10:23:45 server1 sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2
Jan 15 10:23:46 server1 sshd[12345]: Failed password for invalid user root from 192.168.1.100 port 22 ssh2
Jan 15 10:23:47 server1 sshd[12345]: Connection closed by 192.168.1.100 port 22
Jan 15 10:24:01 server1 CRON[12346]: (root) CMD (/usr/bin/apt-get update)
Jan 15 10:25:12 server1 sudo[12347]: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash
Jan 15 10:26:33 server1 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 SRC=10.0.0.5 DST=192.168.1.1 PROTO=TCP DPT=445
Jan 15 10:27:00 server1 nginx[12348]: error: connection refused to upstream
Jan 15 10:27:01 server1 nginx[12348]: error: connection refused to upstream
Jan 15 10:27:02 server1 nginx[12348]: error: connection refused to upstream
Jan 15 10:28:00 server1 systemd[1]: Started Session 123 of user user1
{current_year}-01-15 10:30:00 [Ping] Device: router1 Status: OK Response time: 5ms
{current_year}-01-15 10:30:05 [CPU Load] Device: server1 Status: OK Value: 45 %
{current_year}-01-15 10:30:10 [Memory] Device: server1 Status: Warning Value: 85 % Memory usage high
{current_year}-01-15 10:30:15 [Disk Free] Device: server1 Status: Down Value: 5 % Disk space critical
{current_year}-01-15 10:30:20 [HTTP] Device: webserver1 Status: OK Response time: 120ms
{current_year}-01-15 10:30:25 [SNMP Traffic] Device: switch1 Status: Up Value: 150.5 Mbps
{current_year}-01-15 10:30:30 - Sensor 'Database Connection' on Device 'dbserver1' changed to Down - Connection timeout
""".strip()
        
        count = analyzer.load_from_string(sample_logs)
        print(f"Loaded {count} sample log entries (syslog + PRTG)")
        print("(Run with --help for usage instructions)")
    
    # Generate analysis
    result = analyzer.analyze()
    
    # Output based on flags
    if args.json:
        print("\n--- JSON OUTPUT ---")
        print(json.dumps(result.to_dict(), indent=2))
    elif args.digest:
        print("\n" + analyzer.get_daily_digest_report())
    else:
        print("\n" + analyzer.get_summary_report())
        # Always show daily digest at the end for directory loads
        if args.directory:
            print("\n")
            print(analyzer.get_daily_digest_report())


if __name__ == '__main__':
    main()
