#!/usr/bin/env python3
"""Security Guard + SQLite: speichert jedes Ereignis des Cores strukturiert in einer Datenbank.

Die Datenbank ist die Datenquelle fuer die Dashboards. Das Modul hoert am Logger des Cores mit,
der Core bleibt unveraendert.
"""
import logging, os, platform, sqlite3, sys
from datetime import datetime
import Security_guard_core as core

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,  -- ISO 8601, sortierbar
    host      TEXT NOT NULL,  -- welcher Server, wichtig fuer mehrere Systeme
    system    TEXT NOT NULL,  -- Linux, Darwin, Windows
    event     TEXT NOT NULL,  -- failed, alert, blocked, block_failed, ...
    ip        TEXT,
    message   TEXT,
    origin    TEXT            -- Herkunft, falls das GeoIP-Modul aktiv ist
);
CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents (ip);
CREATE INDEX IF NOT EXISTS idx_incidents_time ON incidents (timestamp);
"""


class Database(logging.Handler):
    """Logging-Handler: jede Meldung mit Ereignis-Feld wird eine Zeile in der Tabelle incidents."""

    def __init__(self, path):
        super().__init__()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")  # Dashboards duerfen lesen, waehrend der Guard schreibt
        self.db.executescript(SCHEMA)

    def emit(self, record):
        if not hasattr(record, "event"):  # Start- und Statusmeldungen sind keine Ereignisse
            return
        try:
            with self.db:  # Transaktion: Commit bei Erfolg, Rollback bei Fehler
                self.db.execute(
                    "INSERT INTO incidents (timestamp, host, system, event, ip, message, origin) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (datetime.fromtimestamp(record.created).isoformat(timespec="seconds"), platform.node(), core.SYSTEM,
                     record.event, record.ip, record.getMessage(), getattr(record, "origin", None)))
        except sqlite3.Error:
            self.handleError(record)  # Datenbankfehler duerfen den Waechter nie stoppen

    def close(self):
        self.db.close()
        super().close()


def main(argv=None):
    parser = core.build_parser()
    parser.add_argument("--db", default=os.path.join(core.HERE, "security_guard.db"), help="SQLite-Datei (Standard: neben dem Skript)")
    args = parser.parse_args(argv)
    try:
        core.log.addHandler(Database(args.db))
    except sqlite3.Error as e:
        sys.exit(f"[FEHLER] Datenbank '{args.db}' nicht nutzbar: {e}")
    return core.run(args)


if __name__ == "__main__":
    sys.exit(main())
