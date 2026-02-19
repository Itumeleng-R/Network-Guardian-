import csv
from datetime import datetime

CSV_FILE = "alerts.csv"
LOG_FILE = "alerts.log"

# ==============================
# INITIALIZE CSV
# ==============================

def initialize_csv():
    try:
        with open(CSV_FILE, "x", newline="") as file:
            writer = csv.writer(file)
            writer.writerow([
                "Timestamp",
                "Severity",
                "Source IP",
                "Classification",
                "Event",
                "Details"
            ])
    except FileExistsError:
        pass


# ==============================
# MAIN LOGGING FUNCTION
# ==============================

def log_alert(severity, source_ip, classification, event, details):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = (
        f"[{timestamp}] "
        f"[{severity}] "
        f"{event} | "
        f"Source: {source_ip} ({classification}) | "
        f"{details}"
    )

    # Print alert to terminal
    print(log_entry)

    # Append to alerts.log (for dashboard)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

    # Append to CSV
    with open(CSV_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            timestamp,
            severity,
            source_ip,
            classification,
            event,
            details
        ])


# ==============================
# READ RECENT ALERTS FOR DASHBOARD
# ==============================

def read_recent_alerts(limit=20):
    try:
        with open("alerts.log", "r") as f:
            lines = f.readlines()
            return [line.strip() for line in lines[-limit:]]
    except FileNotFoundError:
        return ["No alerts logged yet."]


# Initialize CSV on import
initialize_csv()
