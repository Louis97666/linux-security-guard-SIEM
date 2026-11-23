"""Tests fuer das GeoIP-Modul (ohne echte Netzwerkzugriffe). Ausfuehren: python -m unittest -v"""
import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

import Security_guard_core as core
import Security_guard_geoip as geo

HERE = os.path.dirname(os.path.abspath(__file__))
ANSWER = {"success": True, "country": "Germany", "country_code": "DE",
          "connection": {"asn": 3320, "org": "Deutsche Telekom AG"}}


def fake_urlopen(answer):
    return mock.patch.object(geo.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(answer).encode()))


class LookupTest(unittest.TestCase):
    def setUp(self):
        geo.CACHE.clear()

    def test_public_ip(self):
        with fake_urlopen(ANSWER) as urlopen:
            self.assertEqual(geo.lookup("8.8.8.8"), "Germany (DE), Deutsche Telekom AG, AS3320")
            self.assertIn("https://", urlopen.call_args[0][0].full_url)

    def test_result_is_cached(self):
        with fake_urlopen(ANSWER) as urlopen:
            geo.lookup("8.8.8.8")
            geo.lookup("8.8.8.8")
        self.assertEqual(urlopen.call_count, 1)

    def test_private_and_reserved_never_leave_the_network(self):
        with fake_urlopen(ANSWER) as urlopen:
            for ip in ("10.0.0.1", "172.16.5.4", "192.168.1.1", "203.0.113.5", "fd00::1", "fe80::1"):
                self.assertEqual(geo.lookup(ip), "nicht-oeffentliches Netz", ip)
        urlopen.assert_not_called()

    def test_offline_is_not_cached(self):
        with mock.patch.object(geo.urllib.request, "urlopen", side_effect=OSError("offline")), \
                self.assertLogs("security_guard", "WARNING"):
            self.assertIn("nicht erreichbar", geo.lookup("8.8.8.8"))
        self.assertNotIn("8.8.8.8", geo.CACHE)

    def test_unsuccessful_answer(self):
        with fake_urlopen({"success": False}):
            self.assertEqual(geo.lookup("8.8.8.8"), "unbekannt")


class FilterTest(unittest.TestCase):
    def setUp(self):
        geo.CACHE.clear()
        self.geo = geo.GeoIP()
        core.log.addFilter(self.geo)

    def tearDown(self):
        core.log.removeFilter(self.geo)

    def test_only_block_messages_are_enriched(self):
        guard = core.Guard(2, 60, lambda ip: core.block_ip(ip, dry_run=True))
        line = "Failed password for root from 8.8.8.8 port 22 ssh2"
        with fake_urlopen(ANSWER) as urlopen, self.assertLogs("security_guard", "INFO") as logs:
            guard.feed(line, 0)
            guard.feed(line, 1)
        self.assertEqual(urlopen.call_count, 1)  # nur fuer die Sperrmeldung, nicht fuer jeden Fehlversuch
        enriched = [r for r in logs.records if hasattr(r, "origin")]
        self.assertEqual([r.event for r in enriched], ["blocked"])
        self.assertIn("Herkunft: Germany (DE)", enriched[0].getMessage())


class EndToEndTest(unittest.TestCase):
    def test_dry_run_with_reserved_ip_needs_no_network(self):
        audit = os.path.join(HERE, "test_geoip_audit.log")
        self.addCleanup(lambda: os.path.exists(audit) and os.remove(audit))
        lines = "Failed password for root from 203.0.113.5 port 22 ssh2\n" * 3
        r = subprocess.run([sys.executable, os.path.join(HERE, "Security_guard_geoip.py"), "--log", "-",
                            "--dry-run", "--audit", audit], input=lines, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Herkunft: nicht-oeffentliches Netz", r.stderr)


if __name__ == "__main__":
    unittest.main()
