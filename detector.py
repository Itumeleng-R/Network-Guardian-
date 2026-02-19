import requests
import ipaddress
from firewall import block_ip
from alerter import dispatch_alert
from collections import defaultdict
from datetime import datetime, timedelta
from logger import log_alert
from scapy.layers.inet import IP, TCP

# ==============================
# CONFIGURATION
# ==============================

TIME_WINDOW = 5
PORT_SCAN_THRESHOLD = 5
BRUTE_FORCE_THRESHOLD = 5

WHITELIST = {
    "192.168.0.23",
    "192.168.0.1"
}

CRITICAL_PORTS = {22, 3389, 445}

# ==============================
# GEOIP CACHE
# ==============================

geoip_cache = {}

# ==============================
# SESSION STATS
# ==============================

session_stats = {
    "total_alerts": 0,
    "internal_alerts": 0,
    "external_alerts": 0,
    "unique_ips": set()
}

# ==============================
# TRACKING STRUCTURES
# ==============================

port_tracker = defaultdict(list)
brute_force_tracker = defaultdict(list)
alerted_ips = set()

# ==============================
# ML ANOMALY TRACKING
# ==============================

ml_tracker = defaultdict(lambda: {
    "timestamps": [],
    "packet_count": 0
})

# ==============================
# HELPER FUNCTIONS
# ==============================

def get_geoip(ip):

    if ip in geoip_cache:
        return geoip_cache[ip]

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = response.json()

        if data.get("status") == "success":
            country = data.get("country", "Unknown")
            city = data.get("city", "")
            location = f"{country} {city}".strip()
        else:
            location = "Unknown"

    except:
        location = "Unknown"

    geoip_cache[ip] = location
    return location


def classify_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_loopback:
            return "LOOPBACK"
        elif ip_obj.is_private:
            return "INTERNAL"
        else:
            return "EXTERNAL"

    except ValueError:
        return "UNKNOWN"


def assign_severity(classification):
    if classification == "EXTERNAL":
        return "HIGH"
    elif classification == "INTERNAL":
        return "MEDIUM"
    else:
        return "LOW"


def update_session_stats(src_ip, classification):

    session_stats["total_alerts"] += 1
    session_stats["unique_ips"].add(src_ip)

    if classification == "INTERNAL":
        session_stats["internal_alerts"] += 1
    elif classification == "EXTERNAL":
        session_stats["external_alerts"] += 1


def update_behavior_model(src_ip):
    now = datetime.now().timestamp()

    entry = ml_tracker[src_ip]
    entry["timestamps"].append(now)

    entry["timestamps"] = [
        t for t in entry["timestamps"] if now - t <= 60
    ]

    return len(entry["timestamps"])


def is_anomalous(src_ip):
    counts = [len(v["timestamps"]) for v in ml_tracker.values()]

    if len(counts) < 5:
        return False

    mean_val = sum(counts) / len(counts)
    variance = sum((c - mean_val) ** 2 for c in counts) / len(counts)
    std = variance ** 0.5

    current = len(ml_tracker[src_ip]["timestamps"])

    if std == 0:
        return False

    z_score = (current - mean_val) / std

    return z_score >= 3


# ==============================
# MAIN ANALYSIS FUNCTION
# ==============================

def analyze_packet(packet):

    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return

    src_ip = packet[IP].src
    dst_port = packet[TCP].dport

    if src_ip in WHITELIST:
        return

    if not (packet[TCP].flags & 0x02):
        return

    now = datetime.now()

    # =========================
    # PORT SCAN DETECTION
    # =========================

    port_tracker[src_ip].append((dst_port, now))

    port_tracker[src_ip] = [
        (port, t) for (port, t) in port_tracker[src_ip]
        if now - t < timedelta(seconds=TIME_WINDOW)
    ]

    unique_ports = set(port for (port, _) in port_tracker[src_ip])

    if len(unique_ports) >= PORT_SCAN_THRESHOLD and src_ip not in alerted_ips:

        classification = classify_ip(src_ip)
        severity = assign_severity(classification)

        location = ""
        if classification == "EXTERNAL":
            location = get_geoip(src_ip)

        update_session_stats(src_ip, classification)

        details = f"Ports: {sorted(unique_ports)}"
        if location:
            details += f" | Location: {location}"

        log_alert(
            severity,
            src_ip,
            classification,
            "Port Scan Detected",
            details
        )

        if socketio:
                socketio.emit("new_alert", {
                    "alert": details
            })

        dispatch_alert(
            severity,
            src_ip,
            classification,
            "Port Scan Detected",
            details
        )

        if severity == "HIGH" and classification == "EXTERNAL":
            block_ip(src_ip)


        alerted_ips.add(src_ip)

    # =========================
    # BRUTE FORCE DETECTION
    # =========================

    if dst_port in CRITICAL_PORTS:

        brute_force_tracker[src_ip].append(now)

        brute_force_tracker[src_ip] = [
            t for t in brute_force_tracker[src_ip]
            if now - t < timedelta(seconds=TIME_WINDOW)
        ]

        if len(brute_force_tracker[src_ip]) >= BRUTE_FORCE_THRESHOLD:

            classification = classify_ip(src_ip)
            severity = assign_severity(classification)

            location = ""
            if classification == "EXTERNAL":
                location = get_geoip(src_ip)

            update_session_stats(src_ip, classification)

            details = f"Target Port: {dst_port}"
            if location:
                details += f" | Location: {location}"

            log_alert(
                severity,
                src_ip,
                classification,
                "Possible Brute Force Attempt",
                details
            )

            if socketio:
                socketio.emit("new_alert", {
                    "alert": details
            })

            dispatch_alert(
                severity,
                src_ip,
                classification,
                "Possible Brute Force Attempt",
                details
            )

            if severity == "HIGH" and classification == "EXTERNAL":
                block_ip(src_ip)


    # =========================
    # ML ANOMALY DETECTION
    # =========================

    pkt_count = update_behavior_model(src_ip)

    if is_anomalous(src_ip):

        classification = classify_ip(src_ip)
        severity = assign_severity(classification)

        update_session_stats(src_ip, classification)

        details = f"Packet Spike: {pkt_count} packets/min (Anomalous)"

        log_alert(
            severity,
            src_ip,
            classification,
            "ML Anomaly Detected",
            details
        )

        if socketio:
            socketio.emit("new_alert", {
                "alert": details
            })


        dispatch_alert(
            severity,
            src_ip,
            classification,
            "ML Anomaly Detected",
            details
        )

        if severity == "HIGH" and classification == "EXTERNAL":
            block_ip(src_ip)


# ==============================
# EXPORT SESSION STATS
# ==============================

def get_session_stats():
    return session_stats

from flask_socketio import SocketIO
socketio = None

def attach_socketio(sio):
    global socketio
    socketio = sio
