import os
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)
AUDIT_LOG = "incident_audit.log"

HTML_TEMPLATE = """
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <title>Security Guard — Flask Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #0f141b; color: #e6edf3; }
    .cards { display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }
    .card { background: #18202c; padding: 16px 20px; border-radius: 8px; min-width: 170px; border: 1px solid #263244; }
    .card span { display: block; font-size: 13px; color: #9fb0c3; margin-bottom: 6px; }
    .card strong { font-size: 24px; }
    pre { background: #18202c; padding: 16px; border-radius: 8px; border: 1px solid #263244; overflow-x: auto; line-height: 1.45; }
  </style>
</head>
<body>
  <h2>Security Guard — Flask Web Dashboard</h2>
  <div class="cards">
    <div class="card"><span>Warnungen</span><strong id="warnings">0</strong></div>
    <div class="card"><span>Alarme</span><strong id="alarms">0</strong></div>
    <div class="card"><span>Containment-Sperren</span><strong id="containments">0</strong></div>
  </div>
  <pre id="logs">Lade Audit-Einträge...</pre>
  <script>
    async function refreshStatus() {
      try {
        const response = await fetch("/api/status");
        const data = await response.json();
        document.getElementById("warnings").textContent = data.warnings;
        document.getElementById("alarms").textContent = data.alarms;
        document.getElementById("containments").textContent = data.containments;
        document.getElementById("logs").textContent =
          data.lines.length ? data.lines.join("\\n") : "Noch keine Audit-Einträge vorhanden.";
      } catch (err) {
        document.getElementById("logs").textContent = "Fehler beim Laden der Statusdaten: " + err;
      }
    }
    refreshStatus();
    setInterval(refreshStatus, 2000);
  </script>
</body>
</html>
"""


def parse_audit_log(path: str) -> dict:
    warnings = 0
    alarms = 0
    containments = 0
    lines = []

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]

        for line in lines:
            if "[WARNUNG]" in line:
                warnings += 1
            if "[ALARM]" in line:
                alarms += 1
            if "[CONTAINMENT]" in line:
                containments += 1

    return {
        "warnings": warnings,
        "alarms": alarms,
        "containments": containments,
        "lines": lines[-30:],
    }


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/status")
def api_status():
    return jsonify(parse_audit_log(AUDIT_LOG))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)