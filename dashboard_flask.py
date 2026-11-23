#!/usr/bin/env python3
"""Security Guard - Flask-Dashboard: Lagebild im Browser mit JSON-API.

Liest ueber dashboard_data.py die SQLite-Datenbank. Die Seite holt sich alle 2 Sekunden /api/snapshot.
Start: py dashboard_flask.py  ->  http://127.0.0.1:5000   (Demo-Daten: py dashboard_data.py --demo)
"""
import argparse, ipaddress, sys
from flask import Flask, Response, jsonify
import dashboard_data as data

PAGE = """<!doctype html>
<html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Guard - Lagebild</title>
<style>
  :root { --bg:#10151c; --panel:#18202a; --line:#2a323e; --fg:#e4e8ef; --muted:#98a2b3; --accent:#7d9ef5;
          --failed:#f0b56a; --alert:#f2857b; --blocked:#6fcf97; --block_failed:#d19bf5; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 20px max(16px, 3vw); background: var(--bg); color: var(--fg); font: 14px/1.5 "Segoe UI", system-ui, sans-serif; }
  header { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: baseline; gap: 8px; }
  h1 { margin: 0; font-size: 22px; } h2 { margin: 0 0 8px; font-size: 14px; }
  #status { color: var(--muted); } #status.error { color: var(--alert); }
  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 16px 0; }
  .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; min-width: 0; }
  .tile span { color: var(--muted); } .tile b { display: block; font: 700 30px Consolas, monospace; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(380px, 100%), 1fr)); gap: 12px; margin-bottom: 12px; }
  .scroll { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; } th, td { text-align: left; padding: 5px 8px; white-space: nowrap; }
  th { color: var(--muted); font-weight: 500; background: var(--bg); } td.msg { white-space: normal; }
  #chart { display: flex; align-items: flex-end; gap: 6px; height: 200px; padding-top: 18px; }
  .col { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: flex-end; height: 100%; min-width: 0; }
  .bar { width: 70%; background: var(--accent); border-radius: 3px 3px 0 0; }
  .col small { color: var(--muted); font: 11px Consolas, monospace; }
  .failed { color: var(--failed); } .alert { color: var(--alert); } .blocked { color: var(--blocked); } .block_failed { color: var(--block_failed); }
</style></head>
<body>
  <header><h1>Security Guard - Lagebild</h1><span id="status">lade ...</span></header>
  <section class="tiles">
    <div class="panel tile"><span>Fehlversuche</span><b id="failed" class="failed">0</b></div>
    <div class="panel tile"><span>Alarme</span><b id="alert" class="alert">0</b></div>
    <div class="panel tile"><span>Sperren</span><b id="blocked" class="blocked">0</b></div>
    <div class="panel tile"><span>Sperre fehlgeschlagen</span><b id="block_failed" class="block_failed">0</b></div>
  </section>
  <section class="grid">
    <div class="panel scroll"><h2>Top-Angreifer</h2><table><thead><tr><th>IP</th><th>Versuche</th><th>zuletzt</th><th>Herkunft</th></tr></thead><tbody id="top"></tbody></table></div>
    <div class="panel"><h2>Fehlversuche pro Stunde</h2><div id="chart"></div></div>
  </section>
  <section class="panel scroll"><h2>Letzte Ereignisse</h2><table><thead><tr><th>Zeit</th><th>Ereignis</th><th>IP</th><th>Meldung</th></tr></thead><tbody id="recent"></tbody></table></section>
  <script src="/app.js"></script>
</body></html>"""

# Alle Werte werden per textContent eingesetzt, nie als HTML: Logmeldungen enthalten Text vom Angreifer (z. B. Benutzernamen).
SCRIPT = """
const $ = id => document.getElementById(id);
const fmt = (key, value) => key === "timestamp" || key === "last_seen" ? String(value ?? "").replace("T", " ") : (value ?? "");
function el(tag, text, cls) { const e = document.createElement(tag); e.textContent = text; if (cls) e.className = cls; return e; }
function fill(id, items, cols) {
  $(id).replaceChildren(...items.map(item => {
    const tr = document.createElement("tr");
    cols.forEach(c => tr.append(el("td", fmt(c, item[c]), c === "message" ? "msg " + (item.event || "") : (item.event || ""))));
    return tr;
  }));
}
function chart(points) {
  const peak = Math.max(1, ...points.map(p => p.attempts));
  $("chart").replaceChildren(...points.map(p => {
    const bar = el("div", "", "bar");
    bar.style.height = (p.attempts / peak * 85) + "%";
    const col = el("div", "", "col");
    col.append(el("small", p.attempts), bar, el("small", p.hour.slice(-2) + "h"));
    return col;
  }));
  if (!points.length) $("chart").replaceChildren(el("small", "noch keine Fehlversuche"));
}
async function refresh() {
  try {
    const snap = await (await fetch("/api/snapshot")).json();
    for (const [event, count] of Object.entries(snap.counts)) $(event).textContent = count;
    fill("top", snap.top, ["ip", "attempts", "last_seen", "origin"]);
    fill("recent", snap.recent, ["timestamp", "event", "ip", "message"]);
    chart(snap.per_hour);
    $("status").textContent = snap.error || "aktualisiert " + new Date().toLocaleTimeString("de-DE");
    $("status").className = snap.error ? "error" : "";
  } catch (err) {
    $("status").textContent = "Server nicht erreichbar: " + err;
    $("status").className = "error";
  }
}
refresh();
setInterval(refresh, 2000);
"""


def create_app(db=data.DEFAULT_DB):
    """App-Fabrik: eigene Instanz pro Datenbank, praktisch fuer Tests."""
    app = Flask(__name__)
    app.add_url_rule("/", "page", lambda: Response(PAGE, mimetype="text/html"))
    app.add_url_rule("/app.js", "script", lambda: Response(SCRIPT, mimetype="text/javascript"))
    app.add_url_rule("/api/snapshot", "snapshot", lambda: jsonify(data.snapshot(db)))  # JSON-API, auch fuer andere Tools

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"  # nur eigene Skripte
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    return app


def main(argv=None):
    p = argparse.ArgumentParser(description="Flask-Dashboard des Security Guard")
    p.add_argument("--db", default=data.DEFAULT_DB, help="SQLite-Datei des Guard (Standard: neben dem Skript)")
    p.add_argument("--host", default="127.0.0.1", help="Adresse (Standard: nur dieser Rechner)")
    p.add_argument("--port", type=int, default=5000)
    args = p.parse_args(argv)
    try:
        local = args.host == "localhost" or ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        local = False
    if not local:  # das Dashboard hat keine Anmeldung
        print(f"[WARNUNG] Dashboard ohne Anmeldung ist unter {args.host} fuer andere Rechner erreichbar.", file=sys.stderr)
    create_app(args.db).run(args.host, args.port, debug=False)


if __name__ == "__main__":
    main()
