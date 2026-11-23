#!/usr/bin/env python3
"""Gemeinsame Datenschicht aller Dashboards (Tkinter, Flask, Streamlit).

Liest die SQLite-Datenbank des Security Guard nur lesend und liefert alle Kennzahlen als ein dict.
So zeigen alle drei Oberflaechen garantiert dieselben Zahlen.
Demo-Daten fuer Vorfuehrungen: py dashboard_data.py --demo
"""
import argparse, os, random, sqlite3, sys
from contextlib import closing
from datetime import datetime, timedelta
import Security_guard_core as core
from Security_guard_sqlite import SCHEMA

DEFAULT_DB = os.path.join(core.HERE, "security_guard.db")
EVENTS = ("failed", "alert", "blocked", "block_failed")
QUERIES = {  # jede Kennzahl ist genau eine SQL-Abfrage
    "top": "SELECT ip, COUNT(*) AS attempts, MAX(timestamp) AS last_seen, MAX(origin) AS origin FROM incidents "
           "WHERE event = 'failed' GROUP BY ip ORDER BY attempts DESC LIMIT 5",
    "recent": "SELECT timestamp, event, ip, message FROM incidents ORDER BY id DESC LIMIT 20",
    "per_hour": "SELECT * FROM (SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS attempts FROM incidents "
                "WHERE event = 'failed' GROUP BY hour ORDER BY hour DESC LIMIT 24) ORDER BY hour",
    "blocked": "SELECT DISTINCT ip FROM incidents WHERE event = 'blocked' ORDER BY ip",
}


def snapshot(db=DEFAULT_DB):
    """Alle Kennzahlen in einem Rutsch. Fehlt die Datenbank, kommen leere Werte und ein Hinweis in 'error'."""
    data = {"counts": dict.fromkeys(EVENTS, 0), **{key: [] for key in QUERIES}, "error": None}
    if not os.path.exists(db):
        data["error"] = f"Noch keine Datenbank: {db}. Guard mit SQLite-Modul starten oder Demo-Daten erzeugen."
        return data
    try:
        with closing(sqlite3.connect(f"file:{db}?mode=ro", uri=True)) as con:  # nur lesen: Dashboards aendern nie Daten
            con.row_factory = sqlite3.Row
            data["counts"].update(dict(con.execute("SELECT event, COUNT(*) FROM incidents GROUP BY event").fetchall()))
            for key, sql in QUERIES.items():
                data[key] = [dict(row) for row in con.execute(sql)]
    except sqlite3.Error as e:
        data["error"] = f"Datenbank nicht lesbar: {e}"
    return data


def seed_demo(db=DEFAULT_DB, hours=12, seed=None):
    """Fuellt die Datenbank mit erfundenen Angriffen der letzten Stunden, gekennzeichnet als Host 'DEMO'."""
    rng, now = random.Random(seed), datetime.now()
    attackers = ["203.0.113.5", "203.0.113.77", "198.51.100.23", "198.51.100.140", "192.0.2.15", "192.0.2.201"]
    rows = []
    for ip in attackers:
        for _ in range(rng.randint(2, 15)):
            when = (now - timedelta(minutes=rng.randint(0, hours * 60))).isoformat(timespec="seconds")
            rows.append((when, "failed", ip, f"[DEMO] Fehlgeschlagener Login von {ip}"))
        if rng.random() < 0.7:
            rows += [(now.isoformat(timespec="seconds"), event, ip, f"[DEMO] {event} {ip}") for event in ("alert", "blocked")]
    with closing(sqlite3.connect(db)) as con, con:  # schliessen und Transaktion abschliessen
        con.executescript(SCHEMA)
        con.executemany("INSERT INTO incidents (timestamp, host, system, event, ip, message) VALUES (?, 'DEMO', ?, ?, ?, ?)",
                        [(t, core.SYSTEM, e, ip, m) for t, e, ip, m in sorted(rows)])
    return len(rows)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Datenschicht der Dashboards: Kennzahlen anzeigen oder Demo-Daten erzeugen")
    p.add_argument("--db", default=DEFAULT_DB)
    p.add_argument("--demo", action="store_true", help="Demo-Angriffe der letzten 12 Stunden in die Datenbank schreiben")
    args = p.parse_args()
    if args.demo:
        print(f"{seed_demo(args.db)} Demo-Ereignisse in {args.db} geschrieben.")
    data = snapshot(args.db)
    print(data["error"] or data["counts"])
    sys.exit(1 if data["error"] else 0)
