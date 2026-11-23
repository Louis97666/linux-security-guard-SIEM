"""Tests fuer das SQLite-Modul. Ausfuehren: python -m unittest -v"""
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

import Security_guard_core as core
from Security_guard_sqlite import Database

HERE = os.path.dirname(os.path.abspath(__file__))
LINE = "Failed password for root from 203.0.113.5 port 22 ssh2"


class DatabaseTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, core.log, "propagate", core.log.propagate)
        core.log.propagate = False  # Konsolenausgabe im Test unterdruecken, nur die Datenbank hoert zu
        self.path = os.path.join(tempfile.mkdtemp(), "guard.db")
        self.handler = Database(self.path)
        core.log.addHandler(self.handler)

    def tearDown(self):
        core.log.removeHandler(self.handler)
        self.handler.close()

    def rows(self, sql="SELECT event, ip FROM incidents ORDER BY id"):
        with sqlite3.connect(self.path) as db:
            return db.execute(sql).fetchall()

    def test_every_event_becomes_a_row(self):
        guard = core.Guard(2, 60, lambda ip: core.block_ip(ip, dry_run=True))
        guard.feed(LINE, 0)
        guard.feed(LINE, 1)
        self.assertEqual(self.rows(), [("failed", "203.0.113.5"), ("failed", "203.0.113.5"),
                                       ("alert", "203.0.113.5"), ("blocked", "203.0.113.5")])
        timestamp, host, system = self.rows("SELECT timestamp, host, system FROM incidents")[0]
        self.assertRegex(timestamp, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d$")
        self.assertTrue(host)
        self.assertEqual(system, core.SYSTEM)

    def test_status_messages_are_not_stored(self):
        core.log.warning("Keine Admin-/Root-Rechte")  # Warnung ohne Ereignis-Feld
        self.assertEqual(self.rows(), [])

    def test_origin_from_geoip_is_stored(self):
        core.log.critical("gesperrt", extra={"event": "blocked", "ip": "8.8.8.8", "origin": "United States (US)"})
        self.assertEqual(self.rows("SELECT origin FROM incidents"), [("United States (US)",)])

    def test_reopening_keeps_data(self):
        core.log.warning("x", **core.event("failed", "198.51.100.1"))
        Database(self.path).close()  # Schema anlegen ist wiederholbar
        self.assertEqual(len(self.rows()), 1)

    def test_dashboard_can_read_while_guard_writes(self):
        reader = sqlite3.connect(self.path)
        self.addCleanup(reader.close)
        core.log.warning("x", **core.event("failed", "198.51.100.1"))
        self.assertEqual(reader.execute("SELECT COUNT(*) FROM incidents").fetchone(), (1,))
        self.assertEqual(reader.execute("PRAGMA journal_mode").fetchone(), ("wal",))


class EndToEndTest(unittest.TestCase):
    def test_dry_run_writes_database(self):
        folder = tempfile.mkdtemp()
        db = os.path.join(folder, "guard.db")
        r = subprocess.run([sys.executable, os.path.join(HERE, "Security_guard_sqlite.py"), "--log", "-", "--dry-run",
                            "--db", db, "--audit", os.path.join(folder, "audit.log")],
                           input=(LINE + "\n") * 3, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        with sqlite3.connect(db) as con:
            events = [e for (e,) in con.execute("SELECT event FROM incidents ORDER BY id")]
        self.assertEqual(events, ["failed", "failed", "failed", "alert", "blocked"])

    def test_unusable_database_path(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "Security_guard_sqlite.py"), "--db",
                            os.path.join(tempfile.mkdtemp(), "fehlt", "guard.db")], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1)
        self.assertIn("nicht nutzbar", r.stderr)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
