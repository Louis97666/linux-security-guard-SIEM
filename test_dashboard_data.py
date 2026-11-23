"""Tests fuer die gemeinsame Datenschicht der Dashboards. Ausfuehren: python -m unittest -v"""
import os
import tempfile
import unittest

import Security_guard_core as core
import dashboard_data as data
from Security_guard_sqlite import Database


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "guard.db")

    def test_missing_database_gives_empty_values_and_hint(self):
        snap = data.snapshot(self.db)
        self.assertEqual(snap["counts"], {"failed": 0, "alert": 0, "blocked": 0, "block_failed": 0})
        self.assertEqual(snap["top"], [])
        self.assertIn("Noch keine Datenbank", snap["error"])
        self.assertFalse(os.path.exists(self.db))  # lesen legt nie eine Datei an

    def test_reads_what_the_guard_writes(self):
        handler = Database(self.db)
        core.log.addHandler(handler)
        self.addCleanup(core.log.removeHandler, handler)
        self.addCleanup(handler.close)
        self.addCleanup(setattr, core.log, "propagate", core.log.propagate)
        core.log.propagate = False
        guard = core.Guard(3, 60, lambda ip: core.block_ip(ip, dry_run=True))
        for t, ip in enumerate(["203.0.113.5"] * 3 + ["198.51.100.1"]):
            guard.feed(f"Failed password for root from {ip} port 22 ssh2", t)
        snap = data.snapshot(self.db)
        self.assertIsNone(snap["error"])
        self.assertEqual(snap["counts"], {"failed": 4, "alert": 1, "blocked": 1, "block_failed": 0})
        self.assertEqual([(r["ip"], r["attempts"]) for r in snap["top"]], [("203.0.113.5", 3), ("198.51.100.1", 1)])
        self.assertEqual(snap["blocked"], [{"ip": "203.0.113.5"}])
        self.assertEqual(snap["recent"][0]["event"], "failed")  # neuestes zuerst
        self.assertEqual(sum(r["attempts"] for r in snap["per_hour"]), 4)

    def test_demo_data(self):
        count = data.seed_demo(self.db, seed=1)
        snap = data.snapshot(self.db)
        self.assertEqual(sum(snap["counts"].values()), count)
        self.assertLessEqual(len(snap["top"]), 5)
        hours = [r["hour"] for r in snap["per_hour"]]
        self.assertEqual(hours, sorted(hours))  # Diagramm von alt nach neu

    def test_broken_database_file(self):
        with open(self.db, "w") as f:
            f.write("keine Datenbank")
        self.assertIn("nicht lesbar", data.snapshot(self.db)["error"])


if __name__ == "__main__":
    unittest.main()
