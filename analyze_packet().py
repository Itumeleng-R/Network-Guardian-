from collections import defaultdict
from datetime import datetime, timedelta
from logger import log_alert
from scapy.layers.inet import IP, TCP

port_tracker = defaultdict(list)
alerted_ips = set()

TIME_WINDOW = 5
PORT_THRESHOLD = 5

def analyze_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        now = datetime.now()

        # Only count SYN packets (scan behavior)
        if packet[TCP].flags == "S":

            port_tracker[src_ip].append((dst_port, now))

            # Remove old entries
            port_tracker[src_ip] = [
                (port, t)
                for (port, t) in port_tracker[src_ip]
                if now - t < timedelta(seconds=TIME_WINDOW)
            ]

            unique_ports = set(port for (port, _) in port_tracker[src_ip])

            if len(unique_ports) >= PORT_THRESHOLD and src_ip not in alerted_ips:
                log_alert(
                    f"[ALERT] SYN Port Scan Detected from {src_ip} | "
                    f"Ports: {sorted(unique_ports)}"
                )
                alerted_ips.add(src_ip)

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

                try:
                    dispatch_alert(
                        severity,
                        src_ip,
                        classification,
                        "ML Anomaly Detected",
                        details
                    )
                except:
                    pass
