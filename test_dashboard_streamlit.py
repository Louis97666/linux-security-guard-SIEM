"""Tests fuer das Streamlit-Dashboard mit Streamlits eigenem Test-Werkzeug (ohne Browser). Ausfuehren: python -m unittest -v"""
import os
import tempfile
import tomllib
import unittest
from unittest import mock

import dashboard_data as data

try:
    from streamlit.testing.v1 import AppTest
except ImportError:  # Streamlit ist eine Zusatzbibliothek
    AppTest = None

HERE = os.path.dirname(os.path.abspath(__file__))


@unittest.skipIf(AppTest is None, "Streamlit nicht installiert")
class StreamlitDashboardTest(unittest.TestCase):
    def run_app(self, db):
        with mock.patch.dict(os.environ, {"SECURITY_GUARD_DB": db}):
            app = AppTest.from_file(os.path.join(HERE, "dashboard_streamlit.py"), default_timeout=30).run()
        self.assertFalse(app.exception, app.exception)
        return app

    def test_shows_the_shared_snapshot(self):
        db = os.path.join(tempfile.mkdtemp(), "guard.db")
        data.seed_demo(db, seed=4)
        snap = data.snapshot(db)
        app = self.run_app(db)
        self.assertEqual([m.label for m in app.metric], ["Fehlversuche", "Alarme", "Sperren", "Sperre fehlgeschlagen"])
        self.assertEqual([int(m.value) for m in app.metric], [snap["counts"][e] for e in data.EVENTS])
        self.assertEqual(len(app.dataframe[0].value), len(snap["top"]))
        self.assertEqual(len(app.dataframe[1].value), len(snap["recent"]))

    def test_hint_without_database(self):
        app = self.run_app(os.path.join(tempfile.mkdtemp(), "fehlt.db"))
        self.assertIn("Noch keine Datenbank", app.warning[0].value)


class ConfigTest(unittest.TestCase):
    def test_safe_defaults(self):
        with open(os.path.join(HERE, ".streamlit", "config.toml"), "rb") as f:
            config = tomllib.load(f)
        self.assertEqual(config["server"]["address"], "127.0.0.1")  # nicht im Netz erreichbar
        self.assertFalse(config["browser"]["gatherUsageStats"])     # keine Telemetrie


if __name__ == "__main__":
    unittest.main()
