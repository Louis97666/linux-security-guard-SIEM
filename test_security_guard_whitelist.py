"""Tests fuer das Whitelist-Modul. Ausfuehren: python -m unittest -v"""
import os
import subprocess
import sys
import tempfile
import unittest

import Security_guard_core as core
from Security_guard_whitelist import Whitelist

HERE = os.path.dirname(os.path.abspath(__file__))


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class WhitelistTest(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "whitelist.txt")

    def test_entries_networks_comments(self):
        write(self.path, "# Kommentar\n\n192.168.1.50   # Admin\n10.0.0.0/24\n2001:db8::/32\n")
        wl = Whitelist(self.path)
        for ip in ("192.168.1.50", "10.0.0.7", "2001:db8::abcd", "::ffff:10.0.0.9", "127.0.0.1", "::1"):
            self.assertIn(ip, wl, ip)
        for ip in ("192.168.1.51", "10.0.1.1", "203.0.113.5"):
            self.assertNotIn(ip, wl, ip)

    def test_invalid_line_is_skipped_with_warning(self):
        write(self.path, "192.168.1.500\n10.0.0.1\n")
        with self.assertLogs("security_guard", "WARNING") as logs:
            wl = Whitelist(self.path)
        self.assertIn("Zeile 1", logs.output[0])
        self.assertIn("10.0.0.1", wl)

    def test_missing_file_protects_loopback_only(self):
        with self.assertLogs("security_guard", "WARNING"):
            wl = Whitelist(self.path)
        self.assertIn("127.0.0.1", wl)
        self.assertNotIn("10.0.0.1", wl)

    def test_reload_without_restart(self):
        write(self.path, "10.0.0.1\n")
        wl = Whitelist(self.path)
        self.assertNotIn("10.0.0.2", wl)
        write(self.path, "10.0.0.1\n10.0.0.2\n")
        self.assertIn("10.0.0.2", wl)

    def test_guard_never_counts_whitelisted_ip(self):
        write(self.path, "203.0.113.0/24\n")
        blocked = []
        guard = core.Guard(2, 60, lambda ip: blocked.append(ip) or True, Whitelist(self.path))
        line = "Failed password for root from {} port 22 ssh2"
        for t in range(5):
            guard.feed(line.format("203.0.113.5"), t)
            guard.feed(line.format("198.51.100.1"), t)
        self.assertEqual(blocked, ["198.51.100.1"])
        self.assertNotIn("203.0.113.5", guard.hits)

    def test_end_to_end(self):
        write(self.path, "203.0.113.5\n")
        audit = os.path.join(os.path.dirname(self.path), "audit.log")
        lines = "".join(f"Failed password for root from {ip} port 22 ssh2\n" for ip in ["203.0.113.5", "198.51.100.1"] * 3)
        r = subprocess.run([sys.executable, os.path.join(HERE, "Security_guard_whitelist.py"), "--log", "-", "--dry-run",
                            "--whitelist", self.path, "--audit", audit], input=lines, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[WHITELIST] 203.0.113.5", r.stderr)
        self.assertIn("[DRY-RUN]", r.stderr)
        self.assertNotIn("203.0.113.5 port", r.stderr.split("[DRY-RUN]")[1])
        self.assertIn("198.51.100.1", r.stderr.split("[DRY-RUN]")[1])

    def test_rejects_non_positive_limit(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "Security_guard_whitelist.py"), "--limit", "0"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)
        self.assertIn("positive ganze Zahl", r.stderr)


if __name__ == "__main__":
    unittest.main()
