# 🛡️ Fortress Security & Analytics Suite

A comprehensive security orchestration tool and visual dashboard designed for Ubuntu 24.04 LTS. This suite combines real-time intrusion detection, automatic brute-force mitigation, and a web-based analytics interface.

## 🛠️ Components

### 1. AlertSystem (Fortress Monitor v2.1)

The "Heavy Lifter." This script runs as a background service, monitoring logs for malicious activity.

- **Core Function:** Real-time SSH monitoring, Auto-banning via `iptables`, and Geo-IP lookups.
- **Alerting:** Supports Discord/Slack Webhooks and Email notifications.
- **Dependency:** Zero external Python packages (Standard Library only).

### 2. Dashboard (Threat Analytics)

The "Visual Intelligence." A web-based portal to view your server's security posture.

- **Core Function:** Real-time log parsing, IP reputation tracking (via IPInfo.io), and system resource monitoring.
- **Visualization:** Tracking successful vs. failed logins and suspicious command execution.
- **Technology:** Python `http.server`, `matplotlib`, and `numpy`.

---

## 📂 Project Structure

```
.
├── AlertSystem
│   └── fortress_monitor_Version5.py    # The enforcement & alerting engine
├── Dashboard
│   ├── auth_dashboard.py              # Web-based visualization script
│   ├── requirements.txt               # Dashboard dependencies
│   └── run_dashboard.sh               # Initialization & Venv wrapper
└── README.md
```

---

## 🚀 Installation & Setup

### 1. Prepare the Environment

The suite expects specific log and data directories:

```bash
sudo mkdir -p /opt/fortress-monitor/logs /opt/fortress-monitor/data
sudo chmod 700 /opt/fortress-monitor
```

### 2. Deploy the Monitor (Service Mode)

To ensure the **AlertSystem** stays alive after reboots, it is recommended to run it as a systemd service.

```bash
sudo nano /etc/systemd/system/fortress.service
```

**Paste the following:**

```ini
[Unit]
Description=Fortress Monitor Security Suite
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/fortress-monitor
ExecStart=/usr/bin/python3 /opt/fortress-monitor/fortress_monitor_Version5.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### 3. Start the Dashboard

The dashboard uses a virtual environment to manage its specialized plotting libraries.

```bash
cd Dashboard
chmod +x run_dashboard.sh
sudo ./run_dashboard.sh
```

_The dashboard will be available at `http://<your-server-ip>:4567`._

---

## ⚙️ Configuration

### Fortress Monitor (`fortress_monitor_Version5.py`)

Edit the `Config` class inside the script:

- **`BAN_WHITELIST`**: Always add your home/office/Tailscale IPs here!
- **`WEBHOOK_URL`**: Your Discord/Slack webhook for instant alerts.
- **`AUTO_BAN_ENABLED`**: Set to `True` to enable active `iptables` defense.
- **Discord alerts for logins**: Set `WEBHOOK_ENABLED = True` and `WEBHOOK_URL` to your Discord webhook to receive alerts on every login and suspected attack, including the exact event time and geolocation for each IP. If you prefer to only receive attack alerts, set `LOGIN_ALERTS_ENABLED = False`.

### Dashboard (`auth_dashboard.py`)

- **`IPINFO_TOKEN`**: Set your token from ipinfo.io for enhanced IP intelligence.
- **`DASHBOARD_PORT`**: Default is `4567`.

---

## 🛡️ Security Best Practices (The "Fortress" Way)

1. **Tailscale Integration:** If you use Tailscale, ensure your `100.x.x.x` range is in the `BAN_WHITELIST`.
2. **Reverse Shells:** Do not attempt to add reverse shell functionality via Discord webhooks, as this bypasses the security of your system.
3. **Firewall:** Once you confirm Tailscale SSH is working, use `iptables` to block port 22 on your public interface (`enp4s0`) while allowing it on `tailscale0`.

---

## 📊 Monitoring Outputs

- **Live Logs:** `sudo journalctl -u fortress -f`
- **Audit Trail:** `/opt/fortress-monitor/logs/fortress_monitor.log`
- **Daily Reports:** Automatically generated JSON snapshots in the `/data` folder.

---

Colloborated project with [@DDC2000](https://github.com/DDC2000)
