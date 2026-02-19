import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client


# ==============================
# CONFIGURATION
# ==============================

ENABLE_EMAIL = True
ENABLE_SMS = True

# -------------- EMAIL SETTINGS --------------
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "your-email@gmail.com"
EMAIL_PASSWORD = "your-app-password"  # Use App Password, not Gmail password
ALERT_RECIPIENT = "your-email@gmail.com"

# -------------- SMS SETTINGS (TWILIO) --------------
TWILIO_SID = "your_twilio_account_sid"
TWILIO_AUTH = "your_twilio_auth_token"
TWILIO_NUMBER = "+1234567890"
ALERT_PHONE = "+1234567890"


# ==============================
# EMAIL ALERT FUNCTION
# ==============================

def send_email_alert(subject, message):
    if not ENABLE_EMAIL:
        return

    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = ALERT_RECIPIENT

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, ALERT_RECIPIENT, msg.as_string())

        print("[EMAIL] Alert sent successfully!")

    except Exception as e:
        print(f"[EMAIL ERROR] {e}")


# ==============================
# SMS ALERT FUNCTION
# ==============================

def send_sms_alert(message):
    if not ENABLE_SMS:
        return

    try:
        client = Client(TWILIO_SID, TWILIO_AUTH)
        client.messages.create(
            to=ALERT_PHONE,
            from_=TWILIO_NUMBER,
            body=message
        )

        print("[SMS] Alert sent successfully!")

    except Exception as e:
        print(f"[SMS ERROR] {e}")


# ==============================
# COMBINED ALERT DISPATCHER
# ==============================

def dispatch_alert(severity, src_ip, classification, event, details):

    alert_msg = (
        f"Alert Type: {event}\n"
        f"Source IP: {src_ip} ({classification})\n"
        f"Severity: {severity}\n"
        f"Details: {details}"
    )

    subject = f"NETWORK GUARDIAN ALERT — {severity}"

    if severity == "HIGH":
        send_email_alert(subject, alert_msg)
        send_sms_alert(alert_msg)

    elif severity == "MEDIUM":
        send_email_alert(subject, alert_msg)

    # LOW severity → no external alerts
