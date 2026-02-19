📘 README.md — Network Guardian IDS/IPS
🛡️ Network Guardian — Intrusion Detection & Prevention System (IDS/IPS)

A Python-based real-time network security monitor with ML anomaly detection, GeoIP enrichment, automated firewall blocking, email/SMS alerts, and a live web dashboard.

📌 Overview

Network Guardian is a fully featured Intrusion Detection and Prevention System (IDS/IPS) built in Python. It monitors network traffic in real time, detects malicious behavior, classifies threats, enriches attacker data, and can automatically block attackers using Windows Firewall.

This project includes:

🔥 Real-time packet inspection (Scapy)

🚨 Port scan & brute-force attack detection

🤖 Machine Learning anomaly detection (Z-score statistical modeling)

📍 GeoIP attacker location lookup (with caching)

🛡️ Automatic IP blocking (Windows Firewall IPS)

📨 Email & SMS alerting (Gmail + Twilio)

📊 Terminal dashboard (Rich library)

🌐 Full Web dashboard (Flask + SocketIO)

📁 CSV + log file alert storage

🧭 Whitelist & session analytics

This is a portfolio-grade project, perfect for cybersecurity roles in:

Network defense · SOC analyst · Threat detection · Blue teaming · Python security engineer

✨ Features
🧠 1. Machine Learning Anomaly Detection

Network Guardian models packet frequency over time per IP.
Any sudden spike or unusual pattern generates:

ML Anomaly Alert

Severity scoring

Optional auto-block

Uses:

Rolling time window

Z-score statistical deviation

Real-time behavior modeling

🔍 2. Port Scan Detection

Detects SYN-based scans including:

Fast scans

Slow/stealth scans

Multi-port scanning

Threshold-based & time-window controlled.

🔐 3. Brute Force Attack Detection

Monitors traffic to critical ports:

SSH (22)

RDP (3389)

SMB (445)

Flags repeated attempts within a configured window.

🌍 4. GeoIP Enrichment

For external IPs:

Country

City

Cached lookup (fast, offline friendly)

🧱 5. Windows Firewall Auto-Blocking (IPS Mode)

Automatically blocks external HIGH-severity attackers using:

netsh advfirewall firewall add rule ...


Rules are applied instantly.

📊 6. Real-Time Terminal Dashboard

A Rich-powered TUI showing:

Total alerts

Internal & external threats

Unique IPs

Live alert stream

Auto-updating view

🌐 7. Web Dashboard (Flask + SocketIO)

Full browser UI showing:

Session statistics

Live alert feed

Auto-refresh every second

Clean dark theme

📧 8. Email + SMS Alerting

Severity-based alert dispatch:

Severity	Log	  Dashboard	  Email	  SMS
High	    ✅	    ✅	      ✅	    ✅
Medium	  ✅	    ✅	      ✅	    ❌
Low	      ✅     ❌	      ❌      ❌

Supports:

Gmail App Passwords

Twilio SMS API

📝 9. CSV Logging

Every alert is recorded with:

Timestamp

Source IP

Classification

Severity

Event type

Details

🧮 10. Session Statistics

Tracks:

Total alerts

Internal alerts

External alerts

Unique malicious IPs

Packet behavior patterns

🏗️ Project Architecture
Network Guardian
│

├── detector.py          # Core IDS engine

├── logger.py            # Alert logging + CSV

├── alerter.py           # Email & SMS alert system

├── firewall.py          # Auto-block IP logic

├── dashboard.py         # Terminal dashboard

├── web_dashboard.py     # Web dashboard (Flask)

│

├── /templates

│     └── dashboard.html # Web UI

├── / screen grabs

│       └── images.jpeg

│

├── alerts.log           # Human-readable alerts

├── alerts.csv           # Structured alert dataset

├── alerts.txt           # Detection findings

│

└── scanner.py           # Port-scan generator (test tool)

🛠️ Installation
1️⃣ Clone the Repository
git clone https://github.com/<your-username>/Network-Guardian.git
cd Network-Guardian

2️⃣ Install Dependencies
pip install -r requirements.txt


Dependencies include:

scapy
flask
flask-socketio
eventlet
rich
requests
scikit-learn
twilio

3️⃣ Configure Email Alerts

Edit alerter.py:

EMAIL_ADDRESS = "mygmail.com"
EMAIL_PASSWORD = "my-app-password"
ALERT_RECIPIENT = "my@gmail.com"


Use a Gmail APP PASSWORD (not your real account password).

4️⃣ Configure SMS Alerts (Twilio)
TWILIO_SID = "my_sid"
TWILIO_AUTH = "my_token"
TWILIO_NUMBER = "+1234567890"
ALERT_PHONE = "+1234567890"

🚀 Usage
🟦 Run the IDS
python main.py

🟩 Start Terminal Dashboard
python dashboard.py

🟥 Start Web Dashboard
python web_dashboard.py


Open browser:

http://127.0.0.1:5000

🧪 Testing Your IDS

Use the built-in scanner:

python scanner.py


Simulates:

Port scans

High-volume anomalies

Brute-force attempts

Or test with Nmap:

nmap -sS <your-ip>

🧱 Firewall Auto-Block Example

When a HIGH severity attack is detected:

[FIREWALL] BLOCKED IP: 197.14.2.55


A Windows firewall rule will automatically appear under:

Windows Defender Firewall → Inbound Rules

🧠 Machine Learning Detection

Network Guardian builds a rolling behavior model per IP:

Metric	Meaning
timestamps	Packet frequency
packet_count	Overall volume
z-score	Statistical deviation

An anomaly alert fires when:

z_score >= 3  (99.7% deviation)
