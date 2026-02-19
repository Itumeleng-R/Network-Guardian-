from scapy.all import sniff
from detector import analyze_packet, get_session_stats
from logger import initialize_csv
import sys

def packet_callback(packet):
    analyze_packet(packet)

print("Starting Network Guardian...")
print("Monitoring traffic...")

initialize_csv()

try:
    sniff(prn=packet_callback, store=False, iface="WiFi")
except KeyboardInterrupt:
    print("\nShutting down Network Guardian...\n")

    stats = get_session_stats()

    print("===== SESSION SUMMARY =====")
    print(f"Total Alerts: {stats['total_alerts']}")
    print(f"Internal Alerts: {stats['internal_alerts']}")
    print(f"External Alerts: {stats['external_alerts']}")
    print(f"Unique Source IPs: {len(stats['unique_ips'])}")
    print("===========================")

    sys.exit(0)
