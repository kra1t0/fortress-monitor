#!/usr/bin/env python3
"""
Threat Analytics System - Complete security monitoring platform
Run with: sudo python3 threat_analytics.py
"""

import re
import json
import socket
import threading
import webbrowser
import subprocess
import psutil
import pwd
import grp
from datetime import datetime, timedelta
from collections import Counter, defaultdict, deque
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.parse
import time
import os
import sys
import signal

# Configuration
DASHBOARD_PORT = 4567
LOG_FILE = None
MAX_LINES = 50000
REFRESH_INTERVAL = 10  # seconds
IPINFO_TOKEN = "72d3593854f6e4"  # Your token
SCAN_PORTS = True  # Enable port scanning
SCAN_INTERVAL = 300  # Scan every 5 minutes

# Data storage
class ThreatData:
    def __init__(self):
        # Auth data
        self.successful_logins = deque(maxlen=1000)
        self.failed_attempts = deque(maxlen=5000)
        self.bruteforce_attempts = deque(maxlen=500)
        self.suspicious_activities = deque(maxlen=200)
        self.command_history = defaultdict(lambda: deque(maxlen=100))
        self.user_command_history = defaultdict(lambda: deque(maxlen=50))
        self.ip_failures = Counter()
        self.ip_success = Counter()
        self.user_failures = Counter()
        self.user_success = Counter()
        self.hourly_stats = defaultdict(lambda: {'failed': 0, 'success': 0})
        self.country_stats = Counter()
        self.last_scan_time = None
        self.total_events = 0
        self.user_last_login = {}
        
        # Network data
        self.open_ports = []  # List of (port, protocol, service, pid, process)
        self.port_history = defaultdict(lambda: deque(maxlen=100))  # Port activity over time
        self.connections = []  # Current network connections
        self.connection_history = deque(maxlen=1000)
        self.threat_score = 0
        self.threat_indicators = []
        
        # Cache for IP geolocation
        self.ip_cache = {}
        
    def get_ip_info(self, ip):
        """Get geolocation info for an IP address"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                         '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                         '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                         '172.30.', '172.31.', '192.168.', '127.')):
            info = {'country': 'Internal', 'city': 'Local Network', 'org': 'Private IP', 'loc': '0,0'}
            self.ip_cache[ip] = info
            return info
        
        try:
            url = f"https://ipinfo.io/{ip}/json?token={IPINFO_TOKEN}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Threat-Analytics/1.0'})
            with urllib.request.urlopen(req, timeout=2) as response:
                data = json.loads(response.read().decode())
                info = {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'loc': data.get('loc', '0,0')
                }
                self.ip_cache[ip] = info
                if info['country'] != 'Unknown':
                    self.country_stats[info['country']] += 1
                return info
        except Exception:
            info = {'country': 'Unknown', 'city': 'Unknown', 'org': 'Unknown', 'loc': '0,0'}
            self.ip_cache[ip] = info
            return info
    
    def get_user_command_history(self, username):
        """Read user's bash history"""
        if not username or username == 'unknown':
            return []
        
        if username in self.user_command_history and len(self.user_command_history[username]) > 0:
            return list(self.user_command_history[username])
        
        history_paths = [
            f'/home/{username}/.bash_history',
            f'/home/{username}/.zsh_history',
            f'/root/.bash_history',
            f'/root/.zsh_history'
        ]
        
        commands = []
        for hist_path in history_paths:
            if os.path.exists(hist_path) and os.access(hist_path, os.R_OK):
                try:
                    with open(hist_path, 'r') as f:
                        lines = f.readlines()[-50:]
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if ';' in line and line.count(';') > 0:
                                    parts = line.split(';', 1)
                                    if len(parts) > 1:
                                        line = parts[1]
                                commands.append({
                                    'command': line[:100],
                                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                                    'user': username
                                })
                        if commands:
                            break
                except Exception:
                    continue
        
        for cmd in commands[-20:]:
            self.user_command_history[username].append(cmd)
        
        return commands[-20:]
    
    def scan_network(self):
        """Scan for open ports and active connections"""
        new_ports = []
        
        # Get all connections using psutil
        try:
            for conn in psutil.net_connections():
                if conn.status == 'LISTEN':
                    # Listening port
                    port = conn.laddr.port
                    protocol = 'tcp'
                    if conn.type == socket.SOCK_STREAM:
                        protocol = 'tcp'
                    elif conn.type == socket.SOCK_DGRAM:
                        protocol = 'udp'
                    
                    # Get process info
                    pid = conn.pid
                    process_name = 'unknown'
                    process_user = 'unknown'
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            process_name = proc.name()
                            process_user = proc.username()
                        except:
                            pass
                    
                    new_ports.append({
                        'port': port,
                        'protocol': protocol,
                        'service': self.get_service_name(port, protocol),
                        'pid': pid,
                        'process': process_name,
                        'user': process_user,
                        'since': datetime.now().isoformat()
                    })
                    
                    # Update port history
                    self.port_history[port].append({
                        'time': datetime.now(),
                        'connections': len([c for c in psutil.net_connections() if c.laddr.port == port])
                    })
            
            # Store current connections
            self.connections = []
            for conn in psutil.net_connections():
                if conn.raddr:
                    self.connections.append({
                        'local_port': conn.laddr.port,
                        'remote_ip': conn.raddr.ip,
                        'remote_port': conn.raddr.port,
                        'status': conn.status,
                        'pid': conn.pid
                    })
            
            self.connection_history.append({
                'time': datetime.now(),
                'count': len(self.connections)
            })
            
        except Exception as e:
            print(f"Network scan error: {e}")
        
        self.open_ports = new_ports
        self.calculate_threat_score()
    
    def get_service_name(self, port, protocol):
        """Get service name from /etc/services or common ports"""
        try:
            return socket.getservbyport(port, protocol)
        except:
            common_ports = {
                22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                110: 'POP3', 111: 'RPC', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
                443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP',
                3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
                6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
                27017: 'MongoDB'
            }
            return common_ports.get(port, 'unknown')
    
    def calculate_threat_score(self):
        """Calculate overall threat score based on multiple indicators"""
        score = 0
        indicators = []
        
        # Failed login attempts (weight: high)
        recent_failures = len([f for f in self.failed_attempts 
                              if f['time'] > datetime.now() - timedelta(minutes=30)])
        if recent_failures > 100:
            score += 40
            indicators.append(f"High volume of failed logins: {recent_failures} in 30min")
        elif recent_failures > 50:
            score += 25
            indicators.append(f"Moderate failed logins: {recent_failures} in 30min")
        elif recent_failures > 20:
            score += 10
            indicators.append(f"Elevated failed logins: {recent_failures} in 30min")
        
        # Active brute force attacks
        active_bf = len(self.bruteforce_attempts)
        score += active_bf * 15
        if active_bf > 0:
            indicators.append(f"{active_bf} active brute force attacks")
        
        # Open ports (risky services)
        risky_ports = {23, 21, 445, 139, 3389, 5900, 22}
        open_risky = [p for p in self.open_ports if p['port'] in risky_ports]
        if open_risky:
            score += len(open_risky) * 5
            ports_str = ', '.join(str(p['port']) for p in open_risky)
            indicators.append(f"Risky ports open: {ports_str}")
        
        # Unknown processes on open ports
        unknown_procs = [p for p in self.open_ports if p['process'] == 'unknown']
        if unknown_procs:
            score += len(unknown_procs) * 3
            indicators.append(f"{len(unknown_procs)} unknown processes listening")
        
        # Suspicious commands (from history)
        suspicious_cmds = ['wget', 'curl', 'nc', 'netcat', 'nmap', 'chmod', 'chown', 
                          'useradd', 'adduser', 'visudo', 'sudo', 'passwd']
        for user, cmds in self.user_command_history.items():
            for cmd in cmds:
                if any(s in cmd['command'] for s in suspicious_cmds):
                    score += 2
                    indicators.append(f"Suspicious command by {user}: {cmd['command']}")
                    break
        
        # Connections to known bad IPs (simplified - could integrate threat feeds)
        # Here we just flag connections to high-risk countries (if geolocation available)
        for conn in self.connections[:20]:  # Check recent connections
            ip = conn['remote_ip']
            if ip and not ip.startswith(('10.', '192.168.', '172.16.', '127.')):
                info = self.get_ip_info(ip)
                if info['country'] in ['CN', 'RU', 'KP', 'IR']:  # Example high-risk
                    score += 5
                    indicators.append(f"Connection to high-risk country: {ip} ({info['country']})")
                    break
        
        # Cap score at 100
        self.threat_score = min(score, 100)
        self.threat_indicators = indicators[-10:]  # Keep last 10

# Global data store
threat_data = ThreatData()

class LogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.last_position = 0
        
    def extract_user_from_line(self, line):
        patterns = [
            r'user (\w+)',
            r'invalid user (\w+)',
            r'for user (\w+)',
            r'Accepted password for (\w+)',
            r'Failed password for (\w+)',
            r'user=(\w+)',
            r'uid=(\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                username = match.group(1)
                if pattern == r'uid=(\d+)' and username.isdigit():
                    try:
                        username = pwd.getpwuid(int(username)).pw_name
                    except:
                        pass
                return username
        return None
    
    def analyze_line(self, line):
        threat_data.total_events += 1
        
        parts = line.split()
        timestamp = ' '.join(parts[:3]) if len(parts) >= 3 else ''
        
        hour = None
        if len(parts) >= 3 and ':' in parts[2]:
            try:
                hour = int(parts[2].split(':')[0])
            except:
                pass
        
        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
        ip = ips[0] if ips else None
        
        user = self.extract_user_from_line(line)
        
        if re.search(r'Accepted password|Accepted publickey', line, re.IGNORECASE):
            login_data = {
                'timestamp': timestamp,
                'ip': ip,
                'user': user if user else 'unknown',
                'line': line.strip(),
                'time': datetime.now()
            }
            
            if ip:
                login_data['ip_info'] = threat_data.get_ip_info(ip)
                threat_data.ip_success[ip] += 1
                threat_data.user_last_login[user] = {
                    'time': datetime.now(),
                    'ip': ip,
                    'location': f"{login_data['ip_info'].get('country', 'Unknown')}, {login_data['ip_info'].get('city', 'Unknown')}"
                }
            
            if user:
                threat_data.user_success[user] += 1
            
            threat_data.successful_logins.append(login_data)
            
            if hour is not None:
                threat_data.hourly_stats[hour]['success'] += 1
            
            if user and user != 'unknown':
                commands = threat_data.get_user_command_history(user)
                if commands:
                    threat_data.command_history[user] = commands
        
        elif re.search(r'Failed password|authentication failure', line, re.IGNORECASE):
            fail_data = {
                'timestamp': timestamp,
                'ip': ip,
                'user': user if user else 'unknown',
                'line': line.strip(),
                'time': datetime.now()
            }
            
            if ip:
                fail_data['ip_info'] = threat_data.get_ip_info(ip)
                threat_data.ip_failures[ip] += 1
                threat_data.failed_attempts.append(fail_data)
            
            if user:
                threat_data.user_failures[user] += 1
            
            if hour is not None:
                threat_data.hourly_stats[hour]['failed'] += 1
        
        elif re.search(r'Invalid user', line, re.IGNORECASE):
            threat_data.suspicious_activities.append({
                'timestamp': timestamp,
                'type': 'invalid_user',
                'ip': ip,
                'user': user if user else 'unknown',
                'line': line.strip()
            })
    
    def scan_logs(self):
        try:
            with open(self.log_file, 'r') as f:
                f.seek(0, 2)
                current_size = f.tell()
                
                if current_size < self.last_position:
                    self.last_position = 0
                
                f.seek(self.last_position)
                
                for line in f:
                    self.analyze_line(line.strip())
                
                self.last_position = f.tell()
            
            threat_data.last_scan_time = datetime.now()
            self.detect_bruteforce()
            
        except Exception as e:
            print(f"Scan error: {e}")
    
    def detect_bruteforce(self):
        time_threshold = datetime.now() - timedelta(minutes=5)
        recent_failures = defaultdict(list)
        
        for attempt in threat_data.failed_attempts:
            if attempt['time'] > time_threshold and attempt['ip']:
                recent_failures[attempt['ip']].append(attempt)
        
        for ip, attempts in recent_failures.items():
            if len(attempts) >= 10:
                already_flagged = False
                for bf in threat_data.bruteforce_attempts:
                    if bf['ip'] == ip and (datetime.now() - bf['detected']).seconds < 300:
                        already_flagged = True
                        break
                
                if not already_flagged:
                    ip_info = threat_data.get_ip_info(ip)
                    threat_data.bruteforce_attempts.append({
                        'ip': ip,
                        'attempts': len(attempts),
                        'detected': datetime.now(),
                        'users': list(set(a['user'] for a in attempts if a['user'] and a['user'] != 'unknown')),
                        'ip_info': ip_info,
                        'first_seen': min(a['time'] for a in attempts),
                        'last_seen': max(a['time'] for a in attempts)
                    })

# HTTP Request Handler
class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.generate_dashboard().encode())
        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(self.generate_json_stats().encode())
        elif self.path == '/api/commands':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(self.generate_commands_json().encode())
        elif self.path == '/api/network':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(self.generate_network_json().encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass
    
    def generate_dashboard(self):
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Analytics Platform</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.css" />
    <style>
        :root {{
            --bg-primary: #0a0c10;
            --bg-secondary: #1a1e24;
            --bg-tertiary: #252b33;
            --text-primary: #e1e9f0;
            --text-secondary: #9aa8b9;
            --accent-primary: #3b82f6;
            --accent-success: #10b981;
            --accent-danger: #ef4444;
            --accent-warning: #f59e0b;
            --accent-info: #8b5cf6;
            --border-color: #2d3748;
            --card-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1600px;
            margin: 0 auto;
        }}
        
        .header {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            border: 1px solid var(--border-color);
            box-shadow: var(--card-shadow);
        }}
        
        .header h1 {{
            font-size: 2em;
            font-weight: 600;
            background: linear-gradient(135deg, var(--accent-primary), var(--accent-info));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }}
        
        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 0.95em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        
        .stat-card {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            border: 1px solid var(--border-color);
            box-shadow: var(--card-shadow);
            transition: transform 0.2s, border-color 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
            border-color: var(--accent-primary);
        }}
        
        .stat-title {{
            color: var(--text-secondary);
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }}
        
        .stat-value {{
            font-size: 2.2em;
            font-weight: 600;
            margin-bottom: 4px;
        }}
        
        .stat-trend {{
            color: var(--text-secondary);
            font-size: 0.85em;
        }}
        
        .threat-gauge {{
            background: var(--bg-tertiary);
            height: 8px;
            border-radius: 4px;
            margin-top: 10px;
            overflow: hidden;
        }}
        
        .threat-gauge-fill {{
            height: 100%;
            width: 0%;
            transition: width 0.5s;
        }}
        
        .threat-low {{ background: var(--accent-success); }}
        .threat-medium {{ background: var(--accent-warning); }}
        .threat-high {{ background: var(--accent-danger); }}
        
        .chart-container {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid var(--border-color);
            box-shadow: var(--card-shadow);
            height: 400px;
        }}
        
        .map-container {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid var(--border-color);
            box-shadow: var(--card-shadow);
            height: 450px;
        }}
        
        #world-map {{
            height: 400px;
            width: 100%;
            border-radius: 8px;
            background: var(--bg-tertiary);
        }}
        
        .table-container {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 24px;
            border: 1px solid var(--border-color);
            box-shadow: var(--card-shadow);
            overflow-x: auto;
        }}
        
        .section-title {{
            font-size: 1.2em;
            font-weight: 600;
            margin-bottom: 16px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .section-title::before {{
            content: '';
            width: 4px;
            height: 20px;
            background: var(--accent-primary);
            border-radius: 2px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th {{
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 500;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        
        td {{
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
        }}
        
        tr:hover td {{
            background: var(--bg-tertiary);
        }}
        
        .badge {{
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.8em;
            font-weight: 500;
        }}
        
        .badge-danger {{
            background: rgba(239, 68, 68, 0.15);
            color: var(--accent-danger);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }}
        
        .badge-success {{
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-success);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        
        .badge-warning {{
            background: rgba(245, 158, 11, 0.15);
            color: var(--accent-warning);
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}
        
        .badge-info {{
            background: rgba(139, 92, 246, 0.15);
            color: var(--accent-info);
            border: 1px solid rgba(139, 92, 246, 0.3);
        }}
        
        .command-list {{
            max-height: 300px;
            overflow-y: auto;
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 8px;
        }}
        
        .command-item {{
            padding: 8px 12px;
            border-bottom: 1px solid var(--border-color);
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.9em;
            color: var(--text-secondary);
        }}
        
        .command-item:last-child {{
            border-bottom: none;
        }}
        
        .command-item .command {{
            color: var(--accent-primary);
        }}
        
        .command-item .timestamp {{
            font-size: 0.8em;
            color: var(--text-secondary);
            margin-right: 12px;
        }}
        
        .command-item .user {{
            color: var(--accent-success);
            margin-right: 12px;
        }}
        
        .refresh-btn {{
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.9em;
            transition: all 0.2s;
        }}
        
        .refresh-btn:hover {{
            background: var(--accent-primary);
            border-color: var(--accent-primary);
        }}
        
        .last-updated {{
            color: var(--text-secondary);
            font-size: 0.85em;
        }}
        
        .ip-info {{
            color: var(--text-secondary);
            font-size: 0.85em;
        }}
        
        .user-tab {{
            display: inline-block;
            padding: 8px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 8px 8px 0 0;
            cursor: pointer;
            margin-right: 4px;
            color: var(--text-secondary);
        }}
        
        .user-tab.active {{
            background: var(--bg-secondary);
            border-bottom-color: transparent;
            color: var(--accent-primary);
        }}
        
        .user-content {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border-color);
            border-radius: 0 8px 8px 8px;
            padding: 16px;
        }}
        
        .hidden {{
            display: none;
        }}
        
        .flex-row {{
            display: flex;
            gap: 20px;
            margin-bottom: 24px;
        }}
        
        .flex-col {{
            flex: 1;
        }}
        
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: var(--bg-tertiary);
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: var(--border-color);
            border-radius: 4px;
        }}
        
        ::-webkit-scrollbar-thumb:hover {{
            background: var(--text-secondary);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h1>Threat Analytics Platform</h1>
                    <div class="subtitle">Real-time security monitoring â€¢ Authentication â€¢ Network â€¢ Threat scoring</div>
                </div>
                <div>
                    <button class="refresh-btn" onclick="refreshAll()">â†» Refresh</button>
                </div>
            </div>
            <div class="last-updated" style="margin-top: 12px;" id="last-updated">
                Dashboard started at http://{local_ip}:{DASHBOARD_PORT} | Loading...
            </div>
        </div>
        
        <div class="stats-grid" id="stats-cards"></div>
        
        <div class="flex-row">
            <div class="flex-col chart-container">
                <div class="section-title">Authentication Activity (24h)</div>
                <canvas id="activity-chart"></canvas>
            </div>
            <div class="flex-col chart-container">
                <div class="section-title">Network Connections</div>
                <canvas id="connections-chart"></canvas>
            </div>
        </div>
        
        <div class="map-container">
            <div class="section-title">Global Threat Map</div>
            <div id="world-map"></div>
        </div>
        
        <div class="flex-row">
            <div class="flex-col table-container">
                <div class="section-title">Open Ports & Services</div>
                <table id="ports-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Service</th>
                            <th>Process</th>
                            <th>User</th>
                        </tr>
                    </thead>
                    <tbody id="ports-body"></tbody>
                </table>
            </div>
            <div class="flex-col table-container">
                <div class="section-title">Active Threats</div>
                <table id="threats-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Location</th>
                            <th>Attempts</th>
                            <th>Targets</th>
                        </tr>
                    </thead>
                    <tbody id="threats-body"></tbody>
                </table>
            </div>
        </div>
        
        <div class="table-container">
            <div class="section-title">Recent Activity</div>
            <table id="activity-table">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Type</th>
                        <th>User</th>
                        <th>Source</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody id="activity-body"></tbody>
            </table>
        </div>
        
        <div class="table-container">
            <div class="section-title">Command History</div>
            <div id="user-tabs"></div>
            <div id="command-history" class="user-content">
                <div class="command-list" id="command-list">
                    <div class="command-item">Select a user to view command history</div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let activityChart = null;
        let connectionsChart = null;
        let worldMap = null;
        let mapMarkers = [];
        let chartInitialized = false;
        let currentUser = null;
        let commandData = {{}};
        let refreshInterval = null;
        
        function initMap() {{
            worldMap = L.map('world-map').setView([20, 0], 2);
            L.tileLayer('https://{{s}}.basemaps.cartocdn.com/dark_all/{{z}}/{{x}}/{{y}}{{r}}.png', {{
                attribution: 'Â©OpenStreetMap, Â©CartoDB'
            }}).addTo(worldMap);
        }}
        
        function clearMarkers() {{
            if (mapMarkers.length > 0) {{
                mapMarkers.forEach(marker => worldMap.removeLayer(marker));
                mapMarkers = [];
            }}
        }}
        
        function addMarker(lat, lon, title, color) {{
            try {{
                const marker = L.circleMarker([parseFloat(lat), parseFloat(lon)], {{
                    radius: 6,
                    fillColor: color,
                    color: '#fff',
                    weight: 1,
                    opacity: 1,
                    fillOpacity: 0.8
                }}).bindPopup(title);
                marker.addTo(worldMap);
                mapMarkers.push(marker);
            }} catch (e) {{
                console.error('Error adding marker:', e);
            }}
        }}
        
        function refreshAll() {{
            Promise.all([
                fetch('/api/stats').then(r => r.json()),
                fetch('/api/commands').then(r => r.json()),
                fetch('/api/network').then(r => r.json())
            ]).then(([stats, commands, network]) => {{
                commandData = commands;
                updateStats(stats);
                updateTables(stats, network);
                updateCharts(stats, network);
                updateMap(stats);
                updateUserTabs();
                updateThreatGauge(stats.threat_score || 0);
            }});
        }}
        
        function updateStats(data) {{
            document.getElementById('last-updated').innerHTML = 
                `Dashboard started at http://{local_ip}:{DASHBOARD_PORT} | Last updated: ${{new Date().toLocaleString()}} | Log: ${{data.log_file}}`;
            
            const threatClass = data.threat_score < 30 ? 'threat-low' : (data.threat_score < 70 ? 'threat-medium' : 'threat-high');
            
            const statsHtml = `
                <div class="stat-card">
                    <div class="stat-title">Total Events</div>
                    <div class="stat-value">${{data.total_events}}</div>
                    <div class="stat-trend">Last 24h: ${{data.recent_events}}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Failed Attempts</div>
                    <div class="stat-value" style="color: var(--accent-danger);">${{data.failed_count}}</div>
                    <div class="stat-trend">${{data.unique_fail_ips}} unique sources</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Open Ports</div>
                    <div class="stat-value" style="color: var(--accent-info);">${{data.open_ports || 0}}</div>
                    <div class="stat-trend">${{data.risky_ports || 0}} risky</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">Threat Score</div>
                    <div class="stat-value" style="color: ${{data.threat_score < 30 ? '#10b981' : (data.threat_score < 70 ? '#f59e0b' : '#ef4444')}};">${{data.threat_score || 0}}%</div>
                    <div class="threat-gauge">
                        <div class="threat-gauge-fill ${{threatClass}}" style="width: ${{data.threat_score || 0}}%;"></div>
                    </div>
                </div>
            `;
            
            document.getElementById('stats-cards').innerHTML = statsHtml;
        }}
        
        function updateTables(stats, network) {{
            // Ports table
            const portsBody = document.getElementById('ports-body');
            if (network.ports && network.ports.length > 0) {{
                portsBody.innerHTML = network.ports.map(p => `
                    <tr>
                        <td><span style="color: var(--accent-info);">${{p.port}}</span></td>
                        <td>${{p.protocol}}</td>
                        <td>${{p.service}}</td>
                        <td>${{p.process}} (PID: ${{p.pid}})</td>
                        <td>${{p.user}}</td>
                    </tr>
                `).join('');
            }} else {{
                portsBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No open ports detected</td></tr>';
            }}
            
            // Threats table
            const threatsBody = document.getElementById('threats-body');
            if (stats.bruteforce && stats.bruteforce.length > 0) {{
                threatsBody.innerHTML = stats.bruteforce.map(bf => {{
                    const users = bf.users && bf.users.length > 0 ? bf.users.join(', ') : 'multiple';
                    return `
                    <tr>
                        <td><span style="color: var(--accent-danger);">${{bf.ip}}</span></td>
                        <td class="ip-info">${{bf.ip_info.country || 'Unknown'}}, ${{bf.ip_info.city || 'Unknown'}}</td>
                        <td><span class="badge badge-danger">${{bf.attempts}}</span></td>
                        <td>${{users}}</td>
                    </tr>
                `}}).join('');
            }} else {{
                threatsBody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No active threats</td></tr>';
            }}
            
            // Activity table
            const activityBody = document.getElementById('activity-body');
            let activities = [];
            
            if (stats.successful) {{
                stats.successful.slice(0, 5).forEach(s => {{
                    activities.push({{
                        timestamp: s.timestamp,
                        type: 'success',
                        user: s.user,
                        ip: s.ip,
                        location: s.ip_info ? `${{s.ip_info.country || 'Unknown'}}, ${{s.ip_info.city || 'Unknown'}}` : 'Unknown'
                    }});
                }});
            }}
            
            if (stats.failed) {{
                stats.failed.slice(0, 5).forEach(f => {{
                    activities.push({{
                        timestamp: f.timestamp,
                        type: 'failure',
                        user: f.user,
                        ip: f.ip,
                        location: f.ip_info ? `${{f.ip_info.country || 'Unknown'}}, ${{f.ip_info.city || 'Unknown'}}` : 'Unknown'
                    }});
                }});
            }}
            
            activities.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
            
            if (activities.length > 0) {{
                activityBody.innerHTML = activities.slice(0, 10).map(a => `
                    <tr>
                        <td>${{a.timestamp}}</td>
                        <td><span class="badge ${{a.type === 'success' ? 'badge-success' : 'badge-danger'}}">${{a.type}}</span></td>
                        <td><strong>${{a.user}}</strong></td>
                        <td>${{a.ip || 'N/A'}}</td>
                        <td class="ip-info">${{a.location}}</td>
                    </tr>
                `).join('');
            }} else {{
                activityBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No recent activity</td></tr>';
            }}
        }}
        
        function updateCharts(stats, network) {{
            // Authentication chart
            if (stats.chart_labels && stats.chart_labels.length > 0) {{
                const actCtx = document.getElementById('activity-chart').getContext('2d');
                if (!chartInitialized) {{
                    if (activityChart) activityChart.destroy();
                    activityChart = new Chart(actCtx, {{
                        type: 'line',
                        data: {{
                            labels: stats.chart_labels,
                            datasets: [
                                {{
                                    label: 'Failed Attempts',
                                    data: stats.chart_failed,
                                    borderColor: '#ef4444',
                                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                                    borderWidth: 2,
                                    pointRadius: 2,
                                    tension: 0.4
                                }},
                                {{
                                    label: 'Successful Logins',
                                    data: stats.chart_success,
                                    borderColor: '#10b981',
                                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                                    borderWidth: 2,
                                    pointRadius: 2,
                                    tension: 0.4
                                }}
                            ]
                        }},
                        options: {{
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {{
                                legend: {{ labels: {{ color: '#9aa8b9' }} }}
                            }},
                            scales: {{
                                y: {{ ticks: {{ color: '#9aa8b9', stepSize: 1 }}, grid: {{ color: '#2d3748' }} }},
                                x: {{ ticks: {{ color: '#9aa8b9' }}, grid: {{ color: '#2d3748' }} }}
                            }}
                        }}
                    }});
                }} else {{
                    activityChart.data.labels = stats.chart_labels;
                    activityChart.data.datasets[0].data = stats.chart_failed;
                    activityChart.data.datasets[1].data = stats.chart_success;
                    activityChart.update();
                }}
            }}
            
            // Connections chart (mock data for now)
            const connCtx = document.getElementById('connections-chart').getContext('2d');
            if (!connectionsChart) {{
                connectionsChart = new Chart(connCtx, {{
                    type: 'doughnut',
                    data: {{
                        labels: ['Established', 'Listening', 'Other'],
                        datasets: [{{
                            data: [network.established || 0, network.listening || 0, network.other || 0],
                            backgroundColor: ['#10b981', '#3b82f6', '#9aa8b9'],
                            borderWidth: 0
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            legend: {{ labels: {{ color: '#9aa8b9' }} }}
                        }}
                    }}
                }});
            }} else {{
                connectionsChart.data.datasets[0].data = [network.established || 0, network.listening || 0, network.other || 0];
                connectionsChart.update();
            }}
            
            chartInitialized = true;
        }}
        
        function updateMap(stats) {{
            if (!worldMap) return;
            clearMarkers();
            
            if (stats.bruteforce) {{
                stats.bruteforce.forEach(bf => {{
                    if (bf.ip_info && bf.ip_info.loc && bf.ip_info.loc !== '0,0') {{
                        const [lat, lon] = bf.ip_info.loc.split(',').map(Number);
                        if (!isNaN(lat) && !isNaN(lon)) {{
                            addMarker(lat, lon, 
                                `<b>Threat detected</b><br>IP: ${{bf.ip}}<br>Attempts: ${{bf.attempts}}<br>Location: ${{bf.ip_info.country || 'Unknown'}}`,
                                '#ef4444'
                            );
                        }}
                    }}
                }});
            }}
            
            if (stats.failed) {{
                stats.failed.slice(0, 20).forEach(f => {{
                    if (f.ip_info && f.ip_info.loc && f.ip_info.loc !== '0,0') {{
                        const [lat, lon] = f.ip_info.loc.split(',').map(Number);
                        if (!isNaN(lat) && !isNaN(lon)) {{
                            addMarker(lat, lon, 
                                `<b>Failed login</b><br>IP: ${{f.ip}}<br>User: ${{f.user}}<br>Location: ${{f.ip_info.country || 'Unknown'}}`,
                                '#f59e0b'
                            );
                        }}
                    }}
                }});
            }}
        }}
        
        function updateUserTabs() {{
            const users = Object.keys(commandData).filter(u => u !== 'unknown');
            const tabsContainer = document.getElementById('user-tabs');
            const commandList = document.getElementById('command-list');
            
            if (users.length === 0) {{
                tabsContainer.innerHTML = '';
                commandList.innerHTML = '<div class="command-item">No command history available</div>';
                return;
            }}
            
            let tabsHtml = '';
            users.forEach(user => {{
                tabsHtml += `<div class="user-tab ${{user === currentUser ? 'active' : ''}}" onclick="selectUser('${{user}}')">${{user}}</div>`;
            }});
            tabsContainer.innerHTML = tabsHtml;
            
            if (!currentUser || !commandData[currentUser]) {{
                currentUser = users[0];
            }}
            
            selectUser(currentUser);
        }}
        
        window.selectUser = function(user) {{
            currentUser = user;
            
            document.querySelectorAll('.user-tab').forEach(tab => {{
                if (tab.textContent === user) {{
                    tab.classList.add('active');
                }} else {{
                    tab.classList.remove('active');
                }}
            }});
            
            const commandList = document.getElementById('command-list');
            const commands = commandData[user] || [];
            
            if (commands.length === 0) {{
                commandList.innerHTML = '<div class="command-item">No commands found for this user</div>';
                return;
            }}
            
            commandList.innerHTML = commands.map(cmd => `
                <div class="command-item">
                    <span class="timestamp">${{cmd.timestamp}}</span>
                    <span class="command">${{cmd.command}}</span>
                </div>
            `).join('');
        }};
        
        function updateThreatGauge(score) {{
            // Handled in stats card
        }}
        
        window.onload = function() {{
            initMap();
            refreshAll();
            refreshInterval = setInterval(refreshAll, 10000);
        }};
    </script>
</body>
</html>"""
    
    def generate_json_stats(self):
        chart_labels = []
        chart_failed = []
        chart_success = []
        
        for hour in range(24):
            chart_labels.append(f'{hour:02d}:00')
            chart_failed.append(threat_data.hourly_stats.get(hour, {}).get('failed', 0))
            chart_success.append(threat_data.hourly_stats.get(hour, {}).get('success', 0))
        
        successful = [
            {
                'timestamp': s['timestamp'],
                'user': s['user'] if s['user'] else 'unknown',
                'ip': s['ip'],
                'ip_info': s.get('ip_info', {})
            }
            for s in list(threat_data.successful_logins)[-20:]
        ]
        
        failed = [
            {
                'timestamp': f['timestamp'],
                'user': f['user'] if f['user'] else 'unknown',
                'ip': f['ip'],
                'ip_info': f.get('ip_info', {})
            }
            for f in list(threat_data.failed_attempts)[-50:]
        ]
        
        bruteforce = []
        for bf in list(threat_data.bruteforce_attempts)[-20:]:
            bruteforce.append({
                'ip': bf['ip'],
                'attempts': bf['attempts'],
                'users': [u for u in bf['users'][:5] if u],
                'ip_info': bf.get('ip_info', {})
            })
        
        suspicious = [
            {
                'timestamp': s['timestamp'],
                'type': s['type'],
                'line': s['line']
            }
            for s in list(threat_data.suspicious_activities)[-20:]
        ]
        
        threat_data.calculate_threat_score()
        
        stats = {
            'log_file': LOG_FILE,
            'total_events': threat_data.total_events,
            'recent_events': len(threat_data.failed_attempts) + len(threat_data.successful_logins),
            'failed_count': len(threat_data.failed_attempts),
            'success_count': len(threat_data.successful_logins),
            'unique_fail_ips': len(threat_data.ip_failures),
            'unique_success_ips': len(threat_data.ip_success),
            'active_attacks': len(threat_data.bruteforce_attempts),
            'countries_affected': len(threat_data.country_stats),
            'chart_labels': chart_labels,
            'chart_failed': chart_failed,
            'chart_success': chart_success,
            'successful': successful,
            'failed': failed,
            'bruteforce': bruteforce,
            'suspicious': suspicious,
            'threat_score': threat_data.threat_score,
            'threat_indicators': threat_data.threat_indicators,
            'open_ports': len(threat_data.open_ports),
            'risky_ports': len([p for p in threat_data.open_ports if p['port'] in [21,22,23,445,139,3389,5900]])
        }
        
        return json.dumps(stats)
    
    def generate_commands_json(self):
        commands = {}
        for user, cmd_list in threat_data.user_command_history.items():
            if user and user != 'unknown' and cmd_list:
                commands[user] = list(cmd_list)[-50:]
        return json.dumps(commands)
    
    def generate_network_json(self):
        established = len([c for c in threat_data.connections if c['status'] == 'ESTABLISHED'])
        listening = len(threat_data.open_ports)
        other = len(threat_data.connections) - established
        
        ports = []
        for p in threat_data.open_ports:
            ports.append({
                'port': p['port'],
                'protocol': p['protocol'],
                'service': p['service'],
                'pid': p['pid'],
                'process': p['process'],
                'user': p['user']
            })
        
        return json.dumps({
            'ports': ports,
            'established': established,
            'listening': listening,
            'other': other,
            'total_connections': len(threat_data.connections)
        })

def network_scanner():
    """Background thread for network scanning"""
    while True:
        try:
            threat_data.scan_network()
            time.sleep(SCAN_INTERVAL)
        except Exception as e:
            print(f"Network scanner error: {e}")
            time.sleep(60)

def start_dashboard(port):
    server = HTTPServer(('', port), DashboardHandler)
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print(f"\nðŸŒ Threat Analytics Dashboard started at http://100.96.85.52:{port}")
    print(f"   Press Ctrl+C to stop\n")
    
    #webbrowser.open(f'http://{local_ip}:{port}')
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\nðŸ‘‹ Shutting down...")
        server.shutdown()

def main():
    global LOG_FILE
    
    print("""
    â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
    â•‘         Threat Analytics Platform - Complete Security Suite  â•‘
    â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    """)
    
    import argparse
    parser = argparse.ArgumentParser(description='Threat Analytics Platform')
    parser.add_argument('-f', '--file', help='Log file to analyze')
    parser.add_argument('-p', '--port', type=int, default=DASHBOARD_PORT,
                       help=f'Dashboard port (default: {DASHBOARD_PORT})')
    
    args = parser.parse_args()
    
    if args.file:
        LOG_FILE = args.file
    else:
        if os.path.exists('/var/log/auth.log'):
            LOG_FILE = '/var/log/auth.log'
        elif os.path.exists('/var/log/secure'):
            LOG_FILE = '/var/log/secure'
        else:
            print("âŒ Error: Could not find auth log file. Please specify with -f")
            sys.exit(1)
    
    print(f"ðŸ“ Log file: {LOG_FILE}")
    print(f"ðŸ”Œ Dashboard port: {args.port}")
    print(f"ðŸ”‘ IPInfo.io: Connected")
    print(f"ðŸŒ Network scanning: Enabled")
    
    if not os.access(LOG_FILE, os.R_OK):
        print(f"âš ï¸  Warning: Cannot read {LOG_FILE}. Try running with sudo.")
    
    # Create analyzer
    analyzer = LogAnalyzer(LOG_FILE)
    
    # Start background threads
    def scan_loop():
        while True:
            try:
                analyzer.scan_logs()
                time.sleep(REFRESH_INTERVAL)
            except Exception as e:
                print(f"Log scan error: {e}")
                time.sleep(5)
    
    scan_thread = threading.Thread(target=scan_loop, daemon=True)
    scan_thread.start()
    
    # Start network scanner
    net_thread = threading.Thread(target=network_scanner, daemon=True)
    net_thread.start()
    
    # Start dashboard
    start_dashboard(args.port)

if __name__ == "__main__":
    main()
