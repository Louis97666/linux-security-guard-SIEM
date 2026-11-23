"""Tests fuer das Flask-Dashboard (mit Flasks Test-Client, ohne echten Server). Ausfuehren: python -m unittest -v"""
import os
import tempfile
import unittest

import dashboard_data as data
from dashboard_flask import SCRIPT, create_app


class FlaskDashboardTest(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "guard.db")
        self.client = create_app(self.db).test_client()

    def test_page_and_script(self):
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Security Guard - Lagebild", page.data)
        self.assertIn(b'<script src="/app.js">', page.data)
        script = self.client.get("/app.js")
        self.assertEqual(script.mimetype, "text/javascript")

    def test_api_returns_the_shared_snapshot(self):
        data.seed_demo(self.db, seed=3)
        api = self.client.get("/api/snapshot").get_json()
        self.assertEqual(api, data.snapshot(self.db))  # exakt dieselben Zahlen wie Tkinter und Streamlit

    def test_api_without_database(self):
        api = self.client.get("/api/snapshot").get_json()
        self.assertIn("Noch keine Datenbank", api["error"])
        self.assertEqual(api["counts"]["failed"], 0)

    def test_security_headers(self):
        headers = self.client.get("/").headers
        self.assertIn("default-src 'self'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")

    def test_script_never_inserts_html(self):
        self.assertNotIn("innerHTML", SCRIPT)  # Logmeldungen koennen Text vom Angreifer enthalten
        self.assertIn("textContent", SCRIPT)


if __name__ == "__main__":
    unittest.main()
