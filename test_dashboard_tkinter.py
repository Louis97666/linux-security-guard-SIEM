"""Rauchtest fuer das Tkinter-Dashboard (braucht eine grafische Oberflaeche). Ausfuehren: python -m unittest -v"""
import os
import tempfile
import tkinter as tk
import unittest

import dashboard_data as data


class DashboardTest(unittest.TestCase):
    def setUp(self):
        try:
            from dashboard_tkinter import Dashboard
            self.app = Dashboard(os.path.join(tempfile.mkdtemp(), "guard.db"))
        except tk.TclError as e:  # z. B. Server ohne Bildschirm
            self.skipTest(f"keine grafische Oberflaeche: {e}")
        self.addCleanup(self.app.destroy)

    def test_renders_demo_data(self):
        data.seed_demo(self.app.db, seed=2)
        snap = data.snapshot(self.app.db)
        self.app.render(snap)
        self.app.update()
        self.assertEqual(self.app.tiles["failed"]["text"], str(snap["counts"]["failed"]))
        self.assertEqual(len(self.app.top.get_children()), len(snap["top"]))
        self.assertEqual(len(self.app.recent.get_children()), len(snap["recent"]))
        self.assertGreater(len(self.app.chart.find_all()), len(snap["per_hour"]))  # Balken plus Beschriftungen

    def test_shows_hint_without_database(self):
        self.app.render(data.snapshot(self.app.db))
        self.assertIn("Noch keine Datenbank", self.app.status["text"])


if __name__ == "__main__":
    unittest.main()
