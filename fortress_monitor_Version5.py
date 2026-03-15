#!/usr/bin/env python3
"""
================================================================
  FORTRESS MONITOR v2.1 — Zero-Dependency Edition
  Comprehensive SSH Brute Force Detection & Security Auditing
  Target: Ubuntu 24.04.4 LTS

  ZERO external packages. Uses only Python 3 standard library
  + free public API (ip-api.com) for geolocation.

  Run as root:  sudo python3 fortress_monitor.py
================================================================

  What this monitors:
    ✔ Every failed SSH login attempt (password, key, invalid user)
    ✔ Every successful SSH login
    ✔ Attacker IPs with full geolocation (country, city, ISP, VPN)
    ✔ Successful login IPs with geolocation
    ✔ Commands executed via sudo (successful and failed)
    ✔ Session open/close events
    ✔ su (switch user) attempts
    ✔ Real-time brute force detection with configurable thresholds
    ✔ Multi-channel alerts (console, email, webhook)
    ✔ Auto-ban via iptables (optional)
    ✔ Daily summary reports
    ✔ Full audit trail logged to disk with rotation

  Capacity:
    ✔ Tracks up to 100,000 login attempts per cycle
    ✔ Auto-refreshes every 3 days (dumps snapshot to disk, resets memory)
    ✔ All data persisted to log files BEFORE refresh — nothing lost

  Outputs (in /opt/fortress-monitor/logs/):
    fortress_monitor.log  → master event log
    alerts.log            → brute force alerts only
    failed_attempts.log   → every single failed login
    successful_logins.log → every successful login with geo
    commands.log          → sudo/su command audit trail
    daily_report_YYYY-MM-DD.json  → daily summary
    cycle_snapshot_YYYY-MM-DD_HH-MM-SS.json → cycle dump on refresh

  Author: Built for DDC2000 — Security Hardening Initiative
================================================================
"""

import os
import sys
import re
import json
import time
import signal
import socket
import smtplib
import subprocess
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from threading import Thread, Lock, Event
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from http.client import HTTPException
import logging
from logging.handlers import RotatingFileHandler


# ================================================================
#  CONFIGURATION — Edit these values to match your environment
# ================================================================

class Config:
    """All configuration in one place. No external config files needed."""

    # ---- Core Paths ----
    AUTH_LOG_PATH = "/var/log/auth.log"
    LOG_DIR = "/opt/fortress-monitor/logs"
    DATA_DIR = "/opt/fortress-monitor/data"

    # ---- Tracking Capacity ----
    # Maximum login attempts (failed + successful) to hold in memory per cycle
    MAX_TRACKED_ATTEMPTS = 100_000
    # Auto-refresh interval: dump snapshot to disk and reset memory (seconds)
    # 3 days = 259,200 seconds
    CYCLE_REFRESH_SECONDS = 259_200
    # If the attempt cap is hit BEFORE the timer, refresh immediately
    # This means: whichever comes first — 100k attempts or 3 days — triggers refresh

    # ---- Brute Force Detection ----
    MAX_FAILED_ATTEMPTS = 5
    TIME_WINDOW_SECONDS = 300        # 5 minutes
    ALERT_COOLDOWN_SECONDS = 600     # 10 minutes

    # ---- GeoIP (free, no key needed) ----
    GEOIP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query"
    GEOIP_RATE_LIMIT = 45
    GEOIP_ENABLED = True

    # ---- Email Alerts ----
    EMAIL_ENABLED = True
    EMAIL_SMTP_SERVER = "smtp.gmail.com"
    EMAIL_SMTP_PORT = 587
    EMAIL_USE_TLS = True
    EMAIL_SENDER = "fortress@yourdomain.com"
    EMAIL_PASSWORD = "your-app-password-here"
    EMAIL_RECIPIENTS = ["admin@yourdomain.com"]

    # ---- Webhook Alerts ----
    WEBHOOK_ENABLED = False
    WEBHOOK_URL = ""

    # ---- Auto-Ban ----
    AUTO_BAN_ENABLED = True
    BAN_WHITELIST = [
        "127.0.0.1",
        "100.64.0.0/10",     # Tailscale CGNAT range — KEEP THIS
    ]
    BAN_DURATION_SECONDS = 3600

    # ---- Daily Summary Report ----
    DAILY_SUMMARY_ENABLED = True

    # ---- Log Rotation ----
    MAX_LOG_SIZE_MB = 50
    LOG_BACKUP_COUNT = 10

    # ---- Desktop Notifications ----
    DESKTOP_NOTIFY = False


# ================================================================
#  LOG MANAGER
# ================================================================

class LogManager:
    """Creates and manages rotating log files."""

    def __init__(self):
        self.log_dir = Path(Config.LOG_DIR)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        data_dir = Path(Config.DATA_DIR)
        data_dir.mkdir(parents=True, exist_ok=True)

        self.main = self._make_logger("fortress_main", "fortress_monitor.log", console=True)
        self.alerts = self._make_logger("fortress_alerts", "alerts.log")
        self.failed = self._make_logger("fortress_failed", "failed_attempts.log")
        self.success = self._make_logger("fortress_success", "successful_logins.log")
        self.commands = self._make_logger("fortress_commands", "commands.log")

    def _make_logger(self, name, filename, console=False):
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)

        if logger.handlers:
            return logger

        handler = RotatingFileHandler(
            self.log_dir / filename,
            maxBytes=Config.MAX_LOG_SIZE_MB * 1024 * 1024,
            backupCount=Config.LOG_BACKUP_COUNT,
        )
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        ))
        logger.addHandler(handler)

        if console:
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(logging.Formatter(
                "\033[36m%(asctime)s\033[0m | %(message)s", datefmt="%H:%M:%S"
            ))
            logger.addHandler(ch)

        return logger


# ================================================================
#  GEO-IP LOOKUP (uses free ip-api.com — no downloads)
# ================================================================

class GeoLookup:
    """IP geolocation using free public API. Zero dependencies."""

    PRIVATE_PREFIXES = [
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
        "172.30.", "172.31.", "192.168.", "127.", "100.64.",
        "100.65.", "100.66.", "100.67.", "100.68.", "100.69.",
        "100.70.", "100.71.", "100.72.", "100.73.", "100.74.",
        "100.75.", "100.76.", "100.77.", "100.78.", "100.79.",
        "100.80.", "100.81.", "100.82.", "100.83.", "100.84.",
        "100.85.", "100.86.", "100.87.", "100.88.", "100.89.",
        "100.90.", "100.91.", "100.92.", "100.93.", "100.94.",
        "100.95.", "100.96.", "100.97.", "100.98.", "100.99.",
        "100.100.", "100.101.", "100.102.", "100.103.", "100.104.",
        "100.105.", "100.106.", "100.107.", "100.108.", "100.109.",
        "100.110.", "100.111.", "100.112.", "100.113.", "100.114.",
        "100.115.", "100.116.", "100.117.", "100.118.", "100.119.",
        "100.120.", "100.121.", "100.122.", "100.123.", "100.124.",
        "100.125.", "100.126.", "100.127.",
    ]

    def __init__(self, logger):
        self.cache = {}
        self.lock = Lock()
        self.request_timestamps = []
        self.logger = logger

    def _is_private(self, ip):
        for prefix in self.PRIVATE_PREFIXES:
            if ip.startswith(prefix):
                return True
        return False

    def _rate_limit_wait(self):
        """Respect ip-api.com's 45 req/min limit."""
        now = time.time()
        with self.lock:
            self.request_timestamps = [
                t for t in self.request_timestamps if now - t < 60
            ]
            if len(self.request_timestamps) >= Config.GEOIP_RATE_LIMIT:
                wait = 60 - (now - self.request_timestamps[0]) + 0.5
                if wait > 0:
                    time.sleep(wait)
            self.request_timestamps.append(time.time())

    def lookup(self, ip):
        """Look up geolocation for an IP. Returns a dict."""
        if not ip or not Config.GEOIP_ENABLED:
            return self._make_result(ip)

        with self.lock:
            if ip in self.cache:
                return self.cache[ip]

        result = self._make_result(ip)

        if self._is_private(ip):
            result["country"] = "Private/Reserved"
            result["city"] = "Local Network"
            result["is_private"] = True
            with self.lock:
                self.cache[ip] = result
            return result

        try:
            self._rate_limit_wait()
            url = Config.GEOIP_API_URL.format(ip=ip)
            req = Request(url, headers={"User-Agent": "FortressMonitor/2.1"})
            with urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("status") == "success":
                result["country"] = data.get("country", "Unknown")
                result["country_code"] = data.get("countryCode", "??")
                result["region"] = data.get("regionName", "Unknown")
                result["city"] = data.get("city", "Unknown")
                result["zip_code"] = data.get("zip", "")
                result["latitude"] = data.get("lat")
                result["longitude"] = data.get("lon")
                result["timezone"] = data.get("timezone", "")
                result["isp"] = data.get("isp", "Unknown")
                result["org"] = data.get("org", "")
                result["as_number"] = data.get("as", "")
                result["as_name"] = data.get("asname", "")
                result["is_mobile"] = data.get("mobile", False)
                result["is_proxy"] = data.get("proxy", False)
                result["is_hosting"] = data.get("hosting", False)
            else:
                result["error"] = data.get("message", "Lookup failed")

        except (URLError, HTTPError, HTTPException, OSError, json.JSONDecodeError) as e:
            result["error"] = str(e)
            self.logger.warning(f"GeoIP lookup failed for {ip}: {e}")

        with self.lock:
            self.cache[ip] = result
        return result

    def _make_result(self, ip):
        return {
            "ip": ip,
            "country": "Unknown", "country_code": "??",
            "region": "Unknown", "city": "Unknown",
            "zip_code": "", "latitude": None, "longitude": None,
            "timezone": "", "isp": "Unknown", "org": "",
            "as_number": "", "as_name": "",
            "is_mobile": False, "is_proxy": False,
            "is_hosting": False, "is_private": False,
            "error": None,
        }

    def format_location(self, geo):
        """Human-readable location string."""
        parts = []
        for field in ("city", "region", "country"):
            val = geo.get(field, "Unknown")
            if val and val != "Unknown":
                parts.append(val)
        if geo.get("country_code") and geo["country_code"] != "??":
            if parts:
                parts[-1] = f"{parts[-1]} ({geo['country_code']})"

        location = ", ".join(parts) if parts else "Unknown Location"

        flags = []
        if geo.get("is_proxy"):
            flags.append("⚠️VPN/PROXY")
        if geo.get("is_hosting"):
            flags.append("🖥️HOSTING/DC")
        if geo.get("is_mobile"):
            flags.append("📱MOBILE")
        if geo.get("is_private"):
            flags.append("🏠PRIVATE")

        if flags:
            location += f"  [{' | '.join(flags)}]"

        if geo.get("isp") and geo["isp"] != "Unknown":
            location += f"  (ISP: {geo['isp']})"

        return location

    def clear_cache(self):
        """Flush the geo cache on cycle refresh to free memory."""
        with self.lock:
            count = len(self.cache)
            self.cache.clear()
        return count


# ================================================================
#  NOTIFICATION SYSTEM
# ================================================================

class Notifier:
    """Multi-channel alert dispatcher. All built-in, no dependencies."""

    def __init__(self, logs):
        self.logs = logs

    def send_alert(self, subject, message, severity="HIGH"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.logs.alerts.warning(f"[{severity}] {subject} | {message}")

        colors = {
            "CRITICAL": "\033[91m",
            "HIGH":     "\033[93m",
            "MEDIUM":   "\033[95m",
            "LOW":      "\033[94m",
        }
        c = colors.get(severity, "\033[0m")
        r = "\033[0m"
        print(f"\n{c}{'='*70}")
        print(f"  🚨 FORTRESS ALERT [{severity}] — {timestamp}")
        print(f"  {subject}")
        print(f"{'='*70}{r}")
        for line in message.split("\n"):
            print(f"  {line}")
        print(f"{c}{'='*70}{r}\n")

        if Config.EMAIL_ENABLED:
            Thread(target=self._email, args=(subject, message, severity), daemon=True).start()

        if Config.WEBHOOK_ENABLED:
            Thread(target=self._webhook, args=(subject, message, severity), daemon=True).start()

        if Config.DESKTOP_NOTIFY:
            Thread(target=self._desktop, args=(subject, severity), daemon=True).start()

    def _email(self, subject, body, severity):
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = Config.EMAIL_SENDER
            msg["To"] = ", ".join(Config.EMAIL_RECIPIENTS)
            msg["Subject"] = f"🚨 FORTRESS [{severity}]: {subject}"

            html = f"""<html><body style="font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;">
            <h2 style="color:#ff7b72;">🛡️ Fortress Monitor Alert</h2>
            <div style="background:#161b22;padding:16px;border-left:4px solid #ff7b72;white-space:pre-wrap;">{body}</div>
            <p style="color:#8b949e;font-size:12px;margin-top:20px;">
            Fortress Monitor | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Severity: {severity}
            </p></body></html>"""

            msg.attach(MIMEText(body, "plain"))
            msg.attach(MIMEText(html, "html"))

            if Config.EMAIL_USE_TLS:
                server = smtplib.SMTP(Config.EMAIL_SMTP_SERVER, Config.EMAIL_SMTP_PORT)
                server.ehlo()
                server.starttls()
                server.ehlo()
            else:
                server = smtplib.SMTP_SSL(Config.EMAIL_SMTP_SERVER, Config.EMAIL_SMTP_PORT)

            server.login(Config.EMAIL_SENDER, Config.EMAIL_PASSWORD)
            server.send_message(msg)
            server.quit()
            self.logs.main.info("📧 Email alert sent successfully")
        except Exception as e:
            self.logs.main.error(f"📧 Email failed: {e}")

    def _webhook(self, subject, message, severity):
        try:
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
            payload = json.dumps({
                "text": f"{emoji} *FORTRESS [{severity}]*: {subject}\n```{message}```",
                "content": f"{emoji} **FORTRESS [{severity}]**: {subject}\n```{message}```",
            }).encode("utf-8")

            req = Request(
                Config.WEBHOOK_URL,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "FortressMonitor/2.1"},
                method="POST",
            )
            with urlopen(req, timeout=10) as resp:
                pass
            self.logs.main.info("🔔 Webhook alert sent")
        except Exception as e:
            self.logs.main.error(f"🔔 Webhook failed: {e}")

    def _desktop(self, subject, severity):
        try:
            subprocess.run(
                ["notify-send", "-u", "critical", f"🚨 Fortress [{severity}]", subject],
                timeout=5, capture_output=True,
            )
        except Exception:
            pass


# ================================================================
#  BRUTE FORCE TRACKER — with capacity management & auto-refresh
# ================================================================

class BruteForceTracker:
    """
    Tracks failed/successful attempts per IP, detects brute force.

    Capacity system:
      - Tracks up to MAX_TRACKED_ATTEMPTS (100,000) events in memory
      - Every CYCLE_REFRESH_SECONDS (3 days), dumps a full snapshot
        to disk as JSON, then resets all in-memory counters
      - If 100,000 is hit BEFORE 3 days, it dumps early and resets
      - Nothing is ever lost — every event is written to log files
        in real time; the snapshot is an additional summary artifact
      - Cycle number increments forever across restarts (persisted)
    """

    CYCLE_STATE_FILE = Path(Config.DATA_DIR) / "cycle_state.json"

    def __init__(self, notifier, geo, logs):
        self.notifier = notifier
        self.geo = geo
        self.logs = logs

        # ---- Per-cycle tracking (reset on refresh) ----
        self.failed_attempts = defaultdict(list)   # ip -> [timestamps]  (for brute force window)
        self.alerted_ips = {}                       # ip -> last_alert_time
        self.banned_ips = set()
        self.lock = Lock()

        # Per-cycle stats
        self._init_cycle_stats()

        # ---- Lifetime stats (never reset, persisted) ----
        self.lifetime = self._load_lifetime_state()

        # ---- Capacity tracking ----
        self.cycle_attempt_count = 0               # failed + successful this cycle
        self.cycle_start_time = time.time()

    def _init_cycle_stats(self):
        """Initialize/reset per-cycle statistics."""
        self.stats = {
            "total_failed": 0,
            "total_success": 0,
            "total_alerts": 0,
            "total_bans": 0,
            "unique_attacker_ips": set(),
            "unique_success_ips": set(),
            "targeted_users": defaultdict(int),
            "start_time": datetime.now(),
            "attacker_countries": defaultdict(int),
            "attacker_isps": defaultdict(int),
            "methods_seen": defaultdict(int),
            "attacker_details": {},
            "success_details": {},
        }

    def _load_lifetime_state(self):
        """Load persistent lifetime counters from disk."""
        try:
            if self.CYCLE_STATE_FILE.exists():
                with open(self.CYCLE_STATE_FILE, "r") as f:
                    data = json.load(f)
                self.logs.main.info(
                    f"📂 Loaded lifetime state: cycle #{data.get('cycle_number', 0)}, "
                    f"{data.get('lifetime_total_attempts', 0)} total attempts tracked"
                )
                return data
        except Exception as e:
            self.logs.main.warning(f"Could not load cycle state: {e}")

        return {
            "cycle_number": 0,
            "lifetime_total_attempts": 0,
            "lifetime_total_failed": 0,
            "lifetime_total_success": 0,
            "lifetime_total_alerts": 0,
            "lifetime_total_bans": 0,
            "lifetime_total_refreshes": 0,
            "first_start": datetime.now().isoformat(),
        }

    def _save_lifetime_state(self):
        """Persist lifetime counters to disk."""
        try:
            self.CYCLE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(self.CYCLE_STATE_FILE, "w") as f:
                json.dump(self.lifetime, f, indent=2, default=str)
        except Exception as e:
            self.logs.main.error(f"Failed to save cycle state: {e}")

    # ---- Capacity check (called after every recorded event) ----

    def _check_capacity(self):
        """
        Check if we've hit the attempt cap or the time limit.
        If so, dump snapshot and refresh.
        """
        elapsed = time.time() - self.cycle_start_time
        at_cap = self.cycle_attempt_count >= Config.MAX_TRACKED_ATTEMPTS
        at_time = elapsed >= Config.CYCLE_REFRESH_SECONDS

        if at_cap or at_time:
            reason = "ATTEMPT CAP REACHED" if at_cap else "3-DAY TIMER EXPIRED"
            self.logs.main.warning(
                f"🔄 CYCLE REFRESH triggered: {reason} | "
                f"Attempts this cycle: {self.cycle_attempt_count:,} | "
                f"Elapsed: {timedelta(seconds=int(elapsed))}"
            )
            self._do_cycle_refresh(reason)

    def _do_cycle_refresh(self, reason):
        """Dump snapshot to disk, notify, reset in-memory state."""
        with self.lock:
            cycle_num = self.lifetime.get("cycle_number", 0) + 1

            # ---- Build the snapshot ----
            snapshot = {
                "cycle_number": cycle_num,
                "refresh_reason": reason,
                "refresh_time": datetime.now().isoformat(),
                "cycle_started": self.stats["start_time"].isoformat(),
                "cycle_duration_seconds": (datetime.now() - self.stats["start_time"]).total_seconds(),
                "total_attempts_tracked": self.cycle_attempt_count,
                "total_failed": self.stats["total_failed"],
                "total_success": self.stats["total_success"],
                "total_alerts": self.stats["total_alerts"],
                "total_bans": self.stats["total_bans"],
                "unique_attacker_ips": len(self.stats["unique_attacker_ips"]),
                "unique_success_ips": len(self.stats["unique_success_ips"]),
                "top_targeted_users": dict(
                    sorted(self.stats["targeted_users"].items(), key=lambda x: -x[1])[:50]
                ),
                "top_attacker_countries": dict(
                    sorted(self.stats["attacker_countries"].items(), key=lambda x: -x[1])[:30]
                ),
                "top_attacker_isps": dict(
                    sorted(self.stats["attacker_isps"].items(), key=lambda x: -x[1])[:30]
                ),
                "methods_seen": dict(self.stats["methods_seen"]),
                "all_attacker_ips": [
                    {"ip": ip, "location": self.stats["attacker_details"].get(ip, {}).get("location", "Unknown"), "last_seen": self.stats["attacker_details"].get(ip, {}).get("last_seen")}
                    for ip in sorted(self.stats["unique_attacker_ips"])
                ],
                "all_success_ips": [
                    {"ip": ip, "location": self.stats["success_details"].get(ip, {}).get("location", "Unknown"), "last_seen": self.stats["success_details"].get(ip, {}).get("last_seen")}
                    for ip in sorted(self.stats["unique_success_ips"])
                ],
                "lifetime_stats": dict(self.lifetime),
            }

            # ---- Write snapshot to disk ----
            ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"cycle_snapshot_{ts}_cycle{cycle_num}.json"
            filepath = Path(Config.LOG_DIR) / filename

            try:
                with open(filepath, "w") as f:
                    json.dump(snapshot, f, indent=2, default=str)
                self.logs.main.info(f"💾 Cycle snapshot saved: {filepath}")
            except Exception as e:
                self.logs.main.error(f"Failed to save cycle snapshot: {e}")

            # ---- Update lifetime counters ----
            self.lifetime["cycle_number"] = cycle_num
            self.lifetime["lifetime_total_attempts"] += self.cycle_attempt_count
            self.lifetime["lifetime_total_failed"] += self.stats["total_failed"]
            self.lifetime["lifetime_total_success"] += self.stats["total_success"]
            self.lifetime["lifetime_total_alerts"] += self.stats["total_alerts"]
            self.lifetime["lifetime_total_bans"] += self.stats["total_bans"]
            self.lifetime["lifetime_total_refreshes"] += 1
            self.lifetime["last_refresh"] = datetime.now().isoformat()
            self._save_lifetime_state()

            # ---- Reset per-cycle state ----
            self.failed_attempts.clear()
            self.alerted_ips.clear()
            # NOTE: banned_ips is NOT cleared — bans persist across cycles
            self._init_cycle_stats()
            self.cycle_attempt_count = 0
            self.cycle_start_time = time.time()

        # ---- Clear geo cache to free memory ----
        cleared = self.geo.clear_cache()

        # ---- Notify ----
        self.notifier.send_alert(
            f"CYCLE REFRESH #{cycle_num} — {reason}",
            f"Tracked {snapshot['total_attempts_tracked']:,} attempts this cycle\n"
            f"Failed: {snapshot['total_failed']:,} | Success: {snapshot['total_success']:,}\n"
            f"Unique attacker IPs: {snapshot['unique_attacker_ips']:,}\n"
            f"Alerts: {snapshot['total_alerts']} | Bans: {snapshot['total_bans']}\n"
            f"Duration: {timedelta(seconds=int(snapshot['cycle_duration_seconds']))}\n"
            f"Snapshot: {filename}\n"
            f"Geo cache cleared: {cleared} entries\n"
            f"Lifetime total: {self.lifetime['lifetime_total_attempts']:,} attempts across {cycle_num} cycles\n"
            f"Memory reset. Now tracking next {Config.MAX_TRACKED_ATTEMPTS:,} attempts.",
            severity="MEDIUM",
        )

        self.logs.main.info(
            f"🟢 CYCLE #{cycle_num} STARTED — "
            f"Capacity: 0/{Config.MAX_TRACKED_ATTEMPTS:,} | "
            f"Next refresh in {timedelta(seconds=Config.CYCLE_REFRESH_SECONDS)} or at {Config.MAX_TRACKED_ATTEMPTS:,} attempts"
        )

    # ---- Record events ----

    def record_failure(self, ip, user, port, method, raw_line, timestamp=None):
        """Record a failed login attempt and check for brute force."""
        ts = timestamp or time.time()
        event_dt = datetime.fromtimestamp(ts)
        event_time_str = event_dt.strftime("%Y-%m-%d %H:%M:%S")

        with self.lock:
            self.stats["total_failed"] += 1
            self.stats["unique_attacker_ips"].add(ip)
            self.stats["targeted_users"][user] += 1
            self.stats["methods_seen"][method] += 1
            self.failed_attempts[ip].append(ts)
            self.cycle_attempt_count += 1

            # Clean old entries outside the brute force time window
            cutoff = ts - Config.TIME_WINDOW_SECONDS
            self.failed_attempts[ip] = [
                t for t in self.failed_attempts[ip] if t > cutoff
            ]
            attempt_count = len(self.failed_attempts[ip])
            current_count = self.cycle_attempt_count

        # Geo lookup
        geo = self.geo.lookup(ip)
        location = self.geo.format_location(geo)

        # Track attacker geo stats
        with self.lock:
            country = geo.get("country", "Unknown")
            if country != "Unknown":
                self.stats["attacker_countries"][country] += 1
            isp = geo.get("isp", "Unknown")
            if isp != "Unknown":
                self.stats["attacker_isps"][isp] += 1
            self.stats["attacker_details"][ip] = {
                "location": location,
                "last_seen": event_dt.isoformat(),
            }

        # Log every single failed attempt (this goes to disk immediately — never lost)
        log_entry = (
            f"IP={ip} | User={user} | Port={port} | Method={method} | "
            f"Location={location} | "
            f"AttemptTime={event_time_str} | "
            f"Attempts={attempt_count}/{Config.MAX_FAILED_ATTEMPTS} | "
            f"Cycle={current_count:,}/{Config.MAX_TRACKED_ATTEMPTS:,} | "
            f"Raw={raw_line.strip()}"
        )
        self.logs.failed.warning(log_entry)
        self.logs.main.info(f"❌ FAILED LOGIN | {log_entry}")

        # Check brute force threshold
        if attempt_count >= Config.MAX_FAILED_ATTEMPTS:
            self._trigger_brute_force_alert(ip, user, attempt_count, geo, location)

        # Check capacity
        self._check_capacity()

    def _trigger_brute_force_alert(self, ip, user, count, geo, location):
        """Fire alert when brute force threshold is exceeded."""
        now = time.time()

        with self.lock:
            last_alert = self.alerted_ips.get(ip, 0)
            if now - last_alert < Config.ALERT_COOLDOWN_SECONDS:
                return
            self.alerted_ips[ip] = now
            self.stats["total_alerts"] += 1

        subject = f"BRUTE FORCE DETECTED from {ip}"
        message = (
            f"Attacker IP:    {ip}\n"
            f"Location:       {location}\n"
            f"Country:        {geo.get('country', '?')} ({geo.get('country_code', '??')})\n"
            f"City:           {geo.get('city', '?')}\n"
            f"Region:         {geo.get('region', '?')}\n"
            f"ISP:            {geo.get('isp', '?')}\n"
            f"Organization:   {geo.get('org', '?')}\n"
            f"AS:             {geo.get('as_number', '?')} ({geo.get('as_name', '?')})\n"
            f"VPN/Proxy:      {'YES ⚠️' if geo.get('is_proxy') else 'No'}\n"
            f"Hosting/DC:     {'YES ⚠️' if geo.get('is_hosting') else 'No'}\n"
            f"Mobile:         {'Yes' if geo.get('is_mobile') else 'No'}\n"
            f"Last Target:    {user}\n"
            f"Failed Attempts:{count} in {Config.TIME_WINDOW_SECONDS}s\n"
            f"Threshold:      {Config.MAX_FAILED_ATTEMPTS}\n"
            f"Timestamp:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        self.notifier.send_alert(subject, message, severity="CRITICAL")

        if Config.AUTO_BAN_ENABLED and ip not in self.banned_ips:
            self._auto_ban(ip, location)

    def _auto_ban(self, ip, location):
        """Ban IP using iptables."""
        for entry in Config.BAN_WHITELIST:
            if ip == entry or ip.startswith(entry.split("/")[0].rsplit(".", 1)[0]):
                self.logs.main.warning(f"🛑 SKIP BAN — {ip} is whitelisted")
                return

        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10,
            )
            self.banned_ips.add(ip)
            with self.lock:
                self.stats["total_bans"] += 1

            self.logs.main.warning(f"🔨 AUTO-BANNED: {ip} ({location})")
            self.notifier.send_alert(
                f"IP BANNED: {ip}",
                f"Auto-banned {ip} ({location}) for {Config.BAN_DURATION_SECONDS}s",
                severity="HIGH",
            )

            if Config.BAN_DURATION_SECONDS > 0:
                Thread(target=self._unban_later, args=(ip, Config.BAN_DURATION_SECONDS), daemon=True).start()

        except Exception as e:
            self.logs.main.error(f"Ban failed for {ip}: {e}")

    def _unban_later(self, ip, seconds):
        time.sleep(seconds)
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=10,
            )
            self.banned_ips.discard(ip)
            self.logs.main.info(f"🔓 AUTO-UNBANNED: {ip} after {seconds}s")
        except Exception as e:
            self.logs.main.error(f"Unban failed for {ip}: {e}")

    def record_success(self, ip, user, port, method, raw_line):
        """Record a successful login."""
        ts = time.time()
        event_dt = datetime.fromtimestamp(ts)
        event_time_str = event_dt.strftime("%Y-%m-%d %H:%M:%S")
        geo = self.geo.lookup(ip)
        location = self.geo.format_location(geo)

        with self.lock:
            self.stats["total_success"] += 1
            self.stats["unique_success_ips"].add(ip)
            self.cycle_attempt_count += 1
            self.stats["success_details"][ip] = {
                "location": location,
                "last_seen": event_dt.isoformat(),
            }
            current_count = self.cycle_attempt_count

        log_entry = (
            f"IP={ip} | User={user} | Port={port} | Method={method} | "
            f"Location={location} | "
            f"Country={geo.get('country', '?')} | City={geo.get('city', '?')} | "
            f"Region={geo.get('region', '?')} | ISP={geo.get('isp', '?')} | "
            f"VPN/Proxy={'YES' if geo.get('is_proxy') else 'No'} | "
            f"AttemptTime={event_time_str} | "
            f"Cycle={current_count:,}/{Config.MAX_TRACKED_ATTEMPTS:,} | "
            f"Raw={raw_line.strip()}"
        )
        self.logs.success.info(log_entry)
        self.logs.main.info(f"✅ SUCCESSFUL LOGIN | {log_entry}")

        self.notifier.send_alert(
            f"LOGIN from {ip}",
            f"User: {user}\nMethod: {method}\nTime: {event_time_str}\nLocation: {location}\n"
            f"ISP: {geo.get('isp', '?')}\nVPN/Proxy: {'YES' if geo.get('is_proxy') else 'No'}",
            severity="MEDIUM",
        )

        if geo.get("is_proxy") or geo.get("is_hosting"):
            self.notifier.send_alert(
                f"SUSPICIOUS SUCCESSFUL LOGIN from {ip}",
                f"User '{user}' logged in from a VPN/Proxy/Hosting IP!\n"
                f"Location: {location}\n"
                f"ISP: {geo.get('isp', '?')}\n"
                f"This could indicate compromised credentials.",
                severity="HIGH",
            )

        # Check capacity
        self._check_capacity()

    def get_stats(self):
        with self.lock:
            return {
                "total_failed": self.stats["total_failed"],
                "total_success": self.stats["total_success"],
                "total_alerts": self.stats["total_alerts"],
                "total_bans": self.stats["total_bans"],
                "unique_attacker_ips": len(self.stats["unique_attacker_ips"]),
                "unique_success_ips": len(self.stats["unique_success_ips"]),
                "top_targeted_users": dict(
                    sorted(self.stats["targeted_users"].items(), key=lambda x: -x[1])[:20]
                ),
                "cycle_attempt_count": self.cycle_attempt_count,
                "cycle_capacity": Config.MAX_TRACKED_ATTEMPTS,
                "cycle_percent_used": round(
                    (self.cycle_attempt_count / Config.MAX_TRACKED_ATTEMPTS) * 100, 1
                ),
                "cycle_time_elapsed": time.time() - self.cycle_start_time,
                "cycle_time_remaining": max(
                    0, Config.CYCLE_REFRESH_SECONDS - (time.time() - self.cycle_start_time)
                ),
                "cycle_number": self.lifetime.get("cycle_number", 0),
                "lifetime_total_attempts": (
                    self.lifetime.get("lifetime_total_attempts", 0) + self.cycle_attempt_count
                ),
                "uptime_seconds": (datetime.now() - self.stats["start_time"]).total_seconds(),
                "start_time": self.stats["start_time"].isoformat(),
                "attacker_details": dict(self.stats["attacker_details"]),
                "success_details": dict(self.stats["success_details"]),
            }

    def force_refresh(self):
        """Manually trigger a cycle refresh (for testing or emergency)."""
        self._do_cycle_refresh("MANUAL REFRESH")


# ================================================================
#  LOG PARSER — Parses /var/log/auth.log in real-time
# ================================================================

class AuthLogParser:
    """
    Parses Ubuntu auth.log for SSH events, sudo commands, su attempts.
    """

    RE_FAILED_PASSWORD = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    )
    RE_INVALID_USER = re.compile(
        r"Invalid user (\S+) from ([\d.]+) port (\d+)"
    )
    RE_FAILED_KEY = re.compile(
        r"Failed (?:publickey|keyboard-interactive[\w/]*) for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    )
    RE_CLOSED_PREAUTH = re.compile(
        r"Connection closed by (?:authenticating|invalid) user (\S+) ([\d.]+) port (\d+) \[preauth\]"
    )
    RE_DISCONNECTED_PREAUTH = re.compile(
        r"Disconnected from (?:authenticating|invalid) user (\S+) ([\d.]+) port (\d+) \[preauth\]"
    )
    RE_MAX_AUTH = re.compile(
        r"maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    )
    RE_PAM_FAILURE = re.compile(
        r"pam_unix\(sshd:auth\):.*authentication failure.*rhost=([\d.]+)(?:.*user=(\S+))?"
    )
    RE_ACCEPTED_PASSWORD = re.compile(
        r"Accepted password for (\S+) from ([\d.]+) port (\d+)"
    )
    RE_ACCEPTED_KEY = re.compile(
        r"Accepted publickey for (\S+) from ([\d.]+) port (\d+)"
    )
    RE_SESSION_OPEN = re.compile(
        r"pam_unix\(sshd:session\): session opened for user (\S+)"
    )
    RE_SESSION_CLOSE = re.compile(
        r"pam_unix\(sshd:session\): session closed for user (\S+)"
    )
    RE_SUDO_CMD = re.compile(
        r"sudo:\s+(\S+)\s+:.*?;\s+USER=(\S+)\s+;\s+COMMAND=(.*)"
    )
    RE_SUDO_FAILURE = re.compile(
        r"sudo:.*pam_unix\(sudo:auth\):.*authentication failure.*user=(\S+)"
    )
    RE_SU_SESSION = re.compile(
        r"su:\s+pam_unix\(su[-:\w]*session\): session opened for user (\S+) by (\S+)"
    )
    RE_SU_FAILURE = re.compile(
        r"su:\s+(?:pam_unix.*authentication failure|FAILED su for (\S+) by (\S+))"
    )

    def __init__(self, tracker, logs):
        self.tracker = tracker
        self.logs = logs

    def parse_line(self, line):
        """Parse a single auth.log line and dispatch to appropriate handler."""
        if not line.strip():
            return

        # ---- Failed Login Attempts ----

        m = self.RE_FAILED_PASSWORD.search(line)
        if m:
            self.tracker.record_failure(m.group(2), m.group(1), m.group(3), "password", line)
            return

        m = self.RE_INVALID_USER.search(line)
        if m:
            self.tracker.record_failure(m.group(2), m.group(1), m.group(3), "invalid_user", line)
            return

        m = self.RE_FAILED_KEY.search(line)
        if m:
            self.tracker.record_failure(m.group(2), m.group(1), m.group(3), "publickey", line)
            return

        m = self.RE_CLOSED_PREAUTH.search(line)
        if m:
            self.tracker.record_failure(m.group(2), m.group(1), m.group(3), "closed_preauth", line)
            return

        m = self.RE_DISCONNECTED_PREAUTH.search(line)
        if m:
            self.tracker.record_failure(m.group(2), m.group(1), m.group(3), "disconnected_preauth", line)
            return

        m = self.RE_MAX_AUTH.search(line)
        if m:
            self.tracker.record_failure(m.group(2), m.group(1), m.group(3), "max_auth_exceeded", line)
            return

        m = self.RE_PAM_FAILURE.search(line)
        if m:
            user = m.group(2) if m.group(2) else "unknown"
            self.tracker.record_failure(m.group(1), user, "?", "pam_failure", line)
            return

        # ---- Successful Logins ----

        m = self.RE_ACCEPTED_PASSWORD.search(line)
        if m:
            self.tracker.record_success(m.group(2), m.group(1), m.group(3), "password", line)
            return

        m = self.RE_ACCEPTED_KEY.search(line)
        if m:
            self.tracker.record_success(m.group(2), m.group(1), m.group(3), "publickey", line)
            return

        # ---- Sessions ----

        m = self.RE_SESSION_OPEN.search(line)
        if m:
            self.logs.main.info(f"📂 SESSION OPENED | User={m.group(1)}")
            return

        m = self.RE_SESSION_CLOSE.search(line)
        if m:
            self.logs.main.info(f"📁 SESSION CLOSED | User={m.group(1)}")
            return

        # ---- Sudo Commands ----

        m = self.RE_SUDO_CMD.search(line)
        if m:
            user, target_user, command = m.group(1), m.group(2), m.group(3).strip()
            log_entry = f"User={user} | RunAs={target_user} | Command={command} | Raw={line.strip()}"
            self.logs.commands.info(log_entry)
            self.logs.main.info(f"⚡ SUDO COMMAND | {log_entry}")

            dangerous = [
                "rm -rf", "mkfs", "dd if=", "> /dev/sd", "chmod 777",
                "passwd", "useradd", "userdel", "visudo", "iptables",
                "ufw", "systemctl disable", "shutdown", "reboot",
                "curl | sh", "wget | sh", "python -c", "base64 -d",
                "nc -l", "ncat", "/etc/shadow", "/etc/passwd",
            ]
            cmd_lower = command.lower()
            for d in dangerous:
                if d in cmd_lower:
                    self.tracker.notifier.send_alert(
                        f"DANGEROUS COMMAND executed by {user}",
                        f"User: {user}\nRunAs: {target_user}\nCommand: {command}",
                        severity="HIGH",
                    )
                    break
            return

        m = self.RE_SUDO_FAILURE.search(line)
        if m:
            log_entry = f"User={m.group(1)} | SUDO AUTH FAILED | Raw={line.strip()}"
            self.logs.commands.warning(log_entry)
            self.logs.main.warning(f"🔴 SUDO FAILURE | {log_entry}")
            return

        # ---- su (switch user) ----

        m = self.RE_SU_SESSION.search(line)
        if m:
            log_entry = f"From={m.group(2)} | To={m.group(1)} | Raw={line.strip()}"
            self.logs.commands.info(f"SU_SESSION | {log_entry}")
            self.logs.main.info(f"🔄 SU SESSION | {log_entry}")
            return

        m = self.RE_SU_FAILURE.search(line)
        if m:
            log_entry = f"SU_FAILURE | Raw={line.strip()}"
            self.logs.commands.warning(log_entry)
            self.logs.main.warning(f"🔴 SU FAILURE | {log_entry}")
            return


# ================================================================
#  LOG TAILER — Follows auth.log in real-time
# ================================================================

class LogTailer:
    """
    Tails a log file like 'tail -F'.
    Handles log rotation (file renamed/truncated).
    Uses only stdlib.
    """

    def __init__(self, filepath, callback, logger, start_from_end=False):
        self.filepath = filepath
        self.callback = callback
        self.logger = logger
        self.running = Event()
        self.running.set()
        self.start_from_end = start_from_end

    def follow(self):
        self.logger.info(f"📡 Tailing {self.filepath} ...")

        while self.running.is_set():
            try:
                with open(self.filepath, "r") as f:
                    inode = os.stat(self.filepath).st_ino

                    if self.start_from_end:
                        f.seek(0, 2)
                        self.start_from_end = False
                    else:
                        f.seek(0, 2)

                    while self.running.is_set():
                        line = f.readline()
                        if line:
                            try:
                                self.callback(line)
                            except Exception as e:
                                self.logger.error(f"Parse error: {e} | Line: {line.strip()}")
                        else:
                            try:
                                new_inode = os.stat(self.filepath).st_ino
                                if new_inode != inode:
                                    self.logger.info("🔄 Log rotated, reopening...")
                                    break
                            except FileNotFoundError:
                                self.logger.warning("⏳ Log file disappeared, waiting...")
                                time.sleep(1)
                                break
                            time.sleep(0.25)

            except FileNotFoundError:
                self.logger.warning(f"⏳ Waiting for {self.filepath} to appear...")
                time.sleep(2)
            except PermissionError:
                self.logger.error(f"🔒 Permission denied: {self.filepath} — run as root!")
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"Tailer error: {e}")
                time.sleep(2)

    def stop(self):
        self.running.clear()


# ================================================================
#  HISTORICAL LOG PROCESSOR
# ================================================================

class HistoricalProcessor:
    def __init__(self, parser, logs):
        self.parser = parser
        self.logs = logs

    def process(self, filepath, max_lines=10000):
        if not os.path.exists(filepath):
            return 0

        self.logs.main.info(f"📜 Processing historical log (last {max_lines} lines)...")
        count = 0
        try:
            with open(filepath, "r") as f:
                lines = f.readlines()
                recent = lines[-max_lines:] if len(lines) > max_lines else lines
                for line in recent:
                    self.parser.parse_line(line)
                    count += 1
        except Exception as e:
            self.logs.main.error(f"Historical processing error: {e}")

        self.logs.main.info(f"📜 Processed {count} historical log entries")
        return count


# ================================================================
#  DAILY REPORT GENERATOR
# ================================================================

class ReportGenerator:
    def __init__(self, tracker, geo, logs):
        self.tracker = tracker
        self.geo = geo
        self.logs = logs
        self.last_report_date = None

    def run_scheduler(self, stop_event):
        while not stop_event.is_set():
            now = datetime.now()
            today = now.date()

            if self.last_report_date != today and now.hour >= 0:
                if self.last_report_date is not None:
                    self.generate_report()
                self.last_report_date = today

            stop_event.wait(60)

    def generate_report(self):
        try:
            stats = self.tracker.get_stats()
            report = {
                "report_date": datetime.now().isoformat(),
                "summary": stats,
                "top_attacker_ips": self._get_top_attackers(),
            }

            filename = f"daily_report_{datetime.now().strftime('%Y-%m-%d')}.json"
            filepath = Path(Config.LOG_DIR) / filename

            with open(filepath, "w") as f:
                json.dump(report, f, indent=2, default=str)

            self.logs.main.info(f"📊 Daily report saved: {filepath}")

            if Config.EMAIL_ENABLED or Config.WEBHOOK_ENABLED:
                summary = (
                    f"Failed attempts: {stats['total_failed']}\n"
                    f"Successful logins: {stats['total_success']}\n"
                    f"Alerts triggered: {stats['total_alerts']}\n"
                    f"IPs banned: {stats['total_bans']}\n"
                    f"Unique attacker IPs: {stats['unique_attacker_ips']}\n"
                    f"Cycle: {stats['cycle_attempt_count']:,}/{stats['cycle_capacity']:,} "
                    f"({stats['cycle_percent_used']}% used)\n"
                    f"Next refresh in: {timedelta(seconds=int(stats['cycle_time_remaining']))}\n"
                    f"Top targeted users: {json.dumps(stats['top_targeted_users'], indent=2)}"
                )
                self.tracker.notifier.send_alert(
                    "DAILY SECURITY REPORT", summary, severity="LOW"
                )

        except Exception as e:
            self.logs.main.error(f"Report generation failed: {e}")

    def _get_top_attackers(self):
        with self.tracker.lock:
            counts = {
                ip: len(timestamps)
                for ip, timestamps in self.tracker.failed_attempts.items()
            }
        sorted_ips = sorted(counts.items(), key=lambda x: -x[1])[:20]
        result = []
        for ip, count in sorted_ips:
            geo = self.geo.lookup(ip)
            result.append({
                "ip": ip,
                "attempts": count,
                "country": geo.get("country"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "is_proxy": geo.get("is_proxy"),
            })
        return result


# ================================================================
#  CYCLE REFRESH TIMER (background thread)
# ================================================================

class CycleTimer:
    """
    Background thread that forces a time-based cycle refresh
    even if the attempt cap hasn't been reached.
    This ensures the 3-day timer works independently.
    """

    def __init__(self, tracker, logs):
        self.tracker = tracker
        self.logs = logs

    def run(self, stop_event):
        """Check every 60 seconds if the cycle timer has expired."""
        while not stop_event.is_set():
            stop_event.wait(60)
            if stop_event.is_set():
                break

            elapsed = time.time() - self.tracker.cycle_start_time
            if elapsed >= Config.CYCLE_REFRESH_SECONDS:
                self.logs.main.info("⏰ Cycle timer thread detected expiration, triggering refresh...")
                self.tracker._check_capacity()


# ================================================================
#  STATUS DISPLAY
# ================================================================

class StatusDisplay:
    def __init__(self, tracker, logs):
        self.tracker = tracker
        self.logs = logs

    def run(self, stop_event, interval=300):
        while not stop_event.is_set():
            stop_event.wait(interval)
            if stop_event.is_set():
                break

            stats = self.tracker.get_stats()
            uptime = timedelta(seconds=int(stats["uptime_seconds"]))
            refresh_in = timedelta(seconds=int(stats["cycle_time_remaining"]))

            status = (
                f"\n{'─'*70}\n"
                f"  📊 FORTRESS STATUS — Uptime: {uptime}\n"
                f"{'─'*70}\n"
                f"  ❌ Failed attempts:     {stats['total_failed']}\n"
                f"  ✅ Successful logins:   {stats['total_success']}\n"
                f"  🚨 Alerts triggered:    {stats['total_alerts']}\n"
                f"  🔨 IPs banned:          {stats['total_bans']}\n"
                f"  🌍 Unique attacker IPs: {stats['unique_attacker_ips']}\n"
                f"  🏠 Unique success IPs:  {stats['unique_success_ips']}\n"
                f"{'─'*70}\n"
                f"  📦 CYCLE #{stats['cycle_number']} CAPACITY:\n"
                f"     Tracked: {stats['cycle_attempt_count']:,} / {stats['cycle_capacity']:,} "
                f"({stats['cycle_percent_used']}%)\n"
                f"     ████{'█' * int(stats['cycle_percent_used'] / 5)}{'░' * (20 - int(stats['cycle_percent_used'] / 5))}████\n"
                f"     Next refresh in: {refresh_in}\n"
                f"  🔢 Lifetime total: {stats['lifetime_total_attempts']:,} attempts\n"
                f"{'─'*70}"
            )
            print(status)
            self.logs.main.info(
                f"STATUS | Failed={stats['total_failed']} "
                f"Success={stats['total_success']} "
                f"Alerts={stats['total_alerts']} "
                f"Bans={stats['total_bans']} "
                f"Cycle={stats['cycle_attempt_count']:,}/{stats['cycle_capacity']:,} "
                f"({stats['cycle_percent_used']}%)"
            )


# ================================================================
#  MAIN — FORTRESS MONITOR ENTRY POINT
# ================================================================

class FortressMonitor:
    """Main orchestrator."""

    BANNER = """
\033[91m
    ███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗
    ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
    █████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗
    ██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
    ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
\033[93m
              ███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗
              ████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗
              ██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝
              ██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗
              ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║
              ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
\033[0m
\033[36m    ═══════════════════════════════════════════════════════════════════
     SSH Brute Force Detection • Command Auditing • IP Geolocation
     Zero Dependencies • Ubuntu 24.04 LTS • v2.1 Capacity Managed
    ═══════════════════════════════════════════════════════════════════\033[0m
    """

    def __init__(self):
        self.stop_event = Event()
        self.threads = []

    def run(self):
        print(self.BANNER)

        if os.geteuid() != 0:
            print("\033[91m[!] ERROR: Must run as root (sudo python3 fortress_monitor.py)\033[0m")
            sys.exit(1)

        if not os.path.exists(Config.AUTH_LOG_PATH):
            print(f"\033[91m[!] ERROR: {Config.AUTH_LOG_PATH} not found\033[0m")
            print("    Make sure rsyslog/systemd-journald is writing to auth.log")
            sys.exit(1)

        # Initialize core components based on classes defined above
        logs = LogManager()
        logs.main.info("=" * 70)
        logs.main.info("  FORTRESS MONITOR v2.1 STARTING — Capacity Managed Edition")
        logs.main.info("=" * 70)

        geo = GeoLookup(logs.main)
        notifier = Notifier(logs)
        tracker = BruteForceTracker(notifier, geo, logs)
        parser = AuthLogParser(tracker, logs)

        # 1. Process recent history so we aren't starting "blind"
        hist = HistoricalProcessor(parser, logs)
        hist.process(Config.AUTH_LOG_PATH, max_lines=2000)

        # 2. Setup the Log Tailer (starts following from the end of the file)
        tailer = LogTailer(Config.AUTH_LOG_PATH, parser.parse_line, logs.main, start_from_end=True)

        # 3. Setup Signal Handling for Graceful Shutdown
        def signal_handler(sig, frame):
            print("\n\033[93m[!] Shutdown signal received. Cleaning up threads...\033[0m")
            self.stop_event.set()
            tailer.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # 4. Define and Start Background Threads
        bg_tasks = [
            (tailer.follow, "LogTailer"),
            (lambda: ReportGenerator(tracker, geo, logs).run_scheduler(self.stop_event), "ReportGenerator"),
            (lambda: CycleTimer(tracker, logs).run(self.stop_event), "CycleTimer"),
            (lambda: StatusDisplay(tracker, logs).run(self.stop_event), "StatusDisplay")
        ]

        for task_func, name in bg_tasks:
            t = Thread(target=task_func, name=name, daemon=True)
            t.start()
            self.threads.append(t)
            logs.main.info(f"🧵 Started background thread: {name}")

        # Keep main thread alive until stop_event is set
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            pass

# ================================================================
#  ENTRY POINT
# ================================================================

if __name__ == "__main__":
    try:
        monitor = FortressMonitor()
        monitor.run()
    except Exception as e:
        print(f"\033[91m[!] CRITICAL CRASH: {e}\033[0m")
        sys.exit(1)
