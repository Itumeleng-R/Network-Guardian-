import json
from flask import Flask, render_template
from flask_socketio import SocketIO, emit

from detector import get_session_stats
from logger import read_recent_alerts

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

# Push updates every second
@socketio.on("request_update")
def send_update(data):
    stats = get_session_stats()
    alerts = read_recent_alerts(limit=20)

    socketio.emit("dashboard_update", {
        "stats": stats,
        "alerts": alerts
    })

if __name__ == "__main__":
    print("[WEB] Dashboard running at http://127.0.0.1:5000")
    socketio.run(app, host="0.0.0.0", port=5000)
