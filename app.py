# ============================================================
#  Cryptexora IDS - Backend Server
#  Flask web server that handles login, detection, and logs
# ============================================================

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = "cryptexora_secret_2024"   # needed for session handling

# ─────────────────────────────────────────────
#  Simple user credentials (no database needed)
# ─────────────────────────────────────────────
USERS = {
    "admin": "admin123",
    "user":  "user123"
}

# ─────────────────────────────────────────────
#  In-memory log storage (acts like a database)
# ─────────────────────────────────────────────
detection_logs = []


# ─────────────────────────────────────────────
#  Helper: check if user is logged in
# ─────────────────────────────────────────────
def is_logged_in():
    return session.get("logged_in", False)


# ══════════════════════════════════════════════
#  ROUTES
# ══════════════════════════════════════════════

# ---------- Login page ----------
@app.route("/", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username in USERS and USERS[username] == password:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("welcome"))
        else:
            error = "Invalid username or password. Try admin / admin123"

    return render_template("login.html", error=error)


# ---------- Welcome / intro page ----------
@app.route("/welcome")
def welcome():
    if not is_logged_in():
        return redirect(url_for("login"))
    return render_template("welcome.html", username=session.get("username"))


# ---------- Dashboard ----------
@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))

    # Summary counts for dashboard cards
    total   = len(detection_logs)
    attacks = sum(1 for l in detection_logs if l["result"] == "ATTACK")
    normal  = total - attacks

    return render_template("dashboard.html",
                           username=session.get("username"),
                           total=total, attacks=attacks, normal=normal)


# ---------- Detection module ----------
@app.route("/detection")
def detection():
    if not is_logged_in():
        return redirect(url_for("login"))
    return render_template("detection.html", username=session.get("username"))


# ---------- API: Analyze traffic ----------
@app.route("/api/analyze", methods=["POST"])
def analyze():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401

    data        = request.get_json()
    ip          = data.get("ip", "").strip()
    packet_size = int(data.get("packet_size", 0))
    req_type    = data.get("request_type", "").strip().upper()

    # ─────────────────────────────────────────
    #  DETECTION LOGIC  (simple if-else rules)
    #  You can extend these rules easily!
    # ─────────────────────────────────────────
    threats = []
    severity = "LOW"

    # Rule 1: Suspicious IP ranges
    if ip.startswith("192.168.100.") or ip.startswith("10.0.0."):
        threats.append("Suspicious internal IP range detected")
        severity = "MEDIUM"

    # Rule 2: Very large packet → possible DDoS / flood
    if packet_size > 9000:
        threats.append("Abnormally large packet size (possible DDoS)")
        severity = "HIGH"
    elif packet_size > 5000:
        threats.append("Large packet size detected")
        if severity == "LOW":
            severity = "MEDIUM"

    # Rule 3: Dangerous request types
    if req_type in ["DELETE", "PATCH"]:
        threats.append(f"Potentially dangerous request type: {req_type}")
        if severity == "LOW":
            severity = "MEDIUM"

    # Rule 4: Malformed / unknown request type
    if req_type not in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
        threats.append("Unknown or malformed request type")
        severity = "HIGH"

    # Rule 5: Zero-byte packet (suspicious probe)
    if packet_size == 0:
        threats.append("Zero-byte packet (possible port scan / probe)")
        severity = "MEDIUM"

    # ── Final verdict ──
    result  = "ATTACK" if threats else "NORMAL"
    message = "; ".join(threats) if threats else "Traffic appears normal — no threats detected."

    # Save to in-memory log
    log_entry = {
        "id":           len(detection_logs) + 1,
        "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip":           ip,
        "packet_size":  packet_size,
        "request_type": req_type,
        "result":       result,
        "severity":     severity,
        "message":      message,
        "user":         session.get("username")
    }
    detection_logs.append(log_entry)

    return jsonify({
        "result":   result,
        "severity": severity,
        "message":  message,
        "threats":  threats
    })


# ---------- Logs page ----------
@app.route("/logs")
def logs():
    if not is_logged_in():
        return redirect(url_for("login"))
    # Show latest logs first
    reversed_logs = list(reversed(detection_logs))
    return render_template("logs.html",
                           username=session.get("username"),
                           logs=reversed_logs)


# ---------- API: Clear logs ----------
@app.route("/api/clear_logs", methods=["POST"])
def clear_logs():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401
    detection_logs.clear()
    return jsonify({"success": True})


# ---------- Logout ----------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ══════════════════════════════════════════════
if __name__ == "__main__":
    print("\n✅  Cryptexora IDS is running!")
    print("🌐  Open your browser → http://127.0.0.1:5000\n")
    app.run(debug=True)
