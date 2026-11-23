"""Tests fuer den Security-Guard-Core. Ausfuehren: python -m unittest -v"""
import io
import logging
import os
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import Security_guard_core as sg


class ParseTest(unittest.TestCase):
    def test_detects_failures(self):
        cases = {
            "Nov 23 10:00:01 srv sshd[812]: Failed password for root from 203.0.113.5 port 52211 ssh2": "203.0.113.5",
            "Nov 23 10:00:02 srv sshd[812]: Failed password for invalid user admin from 198.51.100.7 port 4 ssh2": "198.51.100.7",
            "2026-11-23T10:00:03 srv sshd-session[9]: Failed password for bob from 2001:db8::1 port 22 ssh2": "2001:db8::1",
            "Nov 23 10:00:04 mac sshd[1]: Failed keyboard-interactive/pam for x from 192.0.2.9 port 1 ssh2": "192.0.2.9",
            "Failed password for from from 192.0.2.10 port 22 ssh2": "192.0.2.10",
            "EventID=4625 from 192.0.2.44": "192.0.2.44",
        }
        for line, ip in cases.items():
            self.assertEqual(sg.parse(line), ip, line)

    def test_ignores_noise(self):
        for line in [
            "sshd[1]: Accepted password for root from 203.0.113.5 port 22 ssh2",
            "sshd[1]: Failed publickey for root from 203.0.113.5 port 22 ssh2",
            "sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=203.0.113.5 user=root",  # Duplikat
            "sshd[1]: Invalid user admin from 203.0.113.5 port 22",  # Duplikat
            "sshd[1]: Failed password for root from 127.0.0.1 port 22 ssh2",
            "EventID=4625 from -",
            "EventID=4625 from ::1",
        ]:
            self.assertIsNone(sg.parse(line), line)


FAIL = "Failed password for root from 203.0.113.5 port 1 ssh2"


class GuardTest(unittest.TestCase):
    def test_blocks_at_limit_once(self):
        blocked = []
        g = sg.Guard(3, 60, lambda ip: blocked.append(ip) or True)
        self.assertEqual([g.feed(FAIL, t) for t in (0, 1, 2, 3)], [None, None, "203.0.113.5", None])
        self.assertEqual(blocked, ["203.0.113.5"])

    def test_window_expires(self):
        g = sg.Guard(3, 60, lambda ip: True)
        self.assertEqual([g.feed(FAIL, t) for t in (0, 30, 61, 80)], [None, None, None, "203.0.113.5"])

    def test_failed_block_allows_retry(self):
        results = iter([False, True])
        g = sg.Guard(2, 60, lambda ip: next(results))
        self.assertEqual([g.feed(FAIL, t) for t in (0, 1, 2, 3)], [None, "203.0.113.5", None, "203.0.113.5"])
        self.assertIn("203.0.113.5", g.blocked)


class FirewallTest(unittest.TestCase):
    def test_commands(self):
        self.assertEqual(sg.firewall_command("1.2.3.4", "Windows")[-1], "remoteip=1.2.3.4")
        self.assertEqual(sg.firewall_command("1.2.3.4", "Darwin")[:2], ["pfctl", "-t"])
        with mock.patch("shutil.which", lambda name: name == "ufw"):
            self.assertEqual(sg.firewall_command("1.2.3.4", "Linux"), ["ufw", "prepend", "deny", "from", "1.2.3.4"])
        with mock.patch("shutil.which", lambda name: None):
            self.assertEqual(sg.firewall_command("1.2.3.4", "Linux")[0], "iptables")
            self.assertEqual(sg.firewall_command("2001:db8::1", "Linux")[0], "ip6tables")

    def test_failed_command_returns_false(self):
        with mock.patch.object(sg, "firewall_command", lambda ip: ["definitely-not-a-binary-xyz"]):
            self.assertFalse(sg.block_ip("1.2.3.4"))


class FollowTest(unittest.TestCase):
    def test_tail_and_rotation(self):
        path = os.path.join(tempfile.mkdtemp(), "auth.log")
        with open(path, "w") as f:
            f.write("alte Zeile\n")
        out = queue.Queue()
        threading.Thread(target=lambda: [out.put(l) for l in sg.follow(path, poll=0.05)], daemon=True).start()
        threading.Event().wait(0.3)
        with open(path, "a") as f:
            f.write("neu 1\n")
        self.assertEqual(out.get(timeout=2), "neu 1\n")
        with open(path, "w") as f:  # Rotation durch Abschneiden (copytruncate)
            f.write("nach rotation\n")
        self.assertEqual(out.get(timeout=2), "nach rotation\n")

    def test_command_source(self):
        lines = sg.follow([sys.executable, "-c", "print('a'); print('b')"])
        self.assertEqual([next(lines), next(lines)], ["a\n", "b\n"])
        with self.assertRaises(RuntimeError):
            next(lines)


class EventTest(unittest.TestCase):
    def test_log_records_carry_event_and_ip(self):
        g = sg.Guard(2, 60, lambda ip: sg.block_ip(ip, dry_run=True))
        with self.assertLogs("security_guard", "INFO") as logs:
            g.feed(FAIL, 0)
            g.feed(FAIL, 1)
        self.assertEqual([(r.event, r.ip) for r in logs.records],
                         [("failed", "203.0.113.5"), ("failed", "203.0.113.5"), ("alert", "203.0.113.5"),
                          ("blocked", "203.0.113.5")])

    def test_failed_block_event(self):
        with mock.patch.object(sg, "firewall_command", lambda ip: ["definitely-not-a-binary-xyz"]),                 self.assertLogs("security_guard", "ERROR") as logs:
            sg.block_ip("1.2.3.4")
        self.assertEqual(logs.records[0].event, "block_failed")


class EndToEndTest(unittest.TestCase):
    def test_stdin_dry_run(self):
        audit = os.path.join(tempfile.mkdtemp(), "audit.log")
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Security_guard_core.py")
        r = subprocess.run([sys.executable, script, "--log", "-", "--dry-run", "--audit", audit],
                           input=(FAIL + "\n") * 3, capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("[DRY-RUN]", r.stderr)
        with open(audit, encoding="utf-8") as f:
            self.assertIn("[ALARM]", f.read())

    def test_missing_file_exits_cleanly(self):
        r = subprocess.run([sys.executable, "Security_guard_core.py", "--log", "gibt-es-nicht.log",
                            "--audit", os.devnull], capture_output=True, text=True, timeout=30,
                           cwd=os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)

    def test_audit_log_defaults_to_script_folder(self):
        here = os.path.dirname(os.path.abspath(sg.__file__))
        self.assertEqual(sg.build_parser().parse_args([]).audit, os.path.join(here, "incident_audit.log"))

    def test_warns_without_admin_rights(self):
        args = sg.build_parser().parse_args(["--log", "-", "--audit", os.path.join(tempfile.mkdtemp(), "a.log")])
        with mock.patch.object(sg, "is_admin", return_value=False), mock.patch("sys.stdin", io.StringIO("")), \
                self.assertLogs("security_guard", "INFO") as logs:
            self.assertEqual(sg.run(args), 0)
        self.assertTrue(any("Keine Admin-/Root-Rechte" in m for m in logs.output))
        self.assertTrue(any("Audit-Log:" in m for m in logs.output))
        for h in logging.getLogger().handlers[:]:  # FileHandler aus basicConfig wieder schliessen
            h.close()
            logging.getLogger().removeHandler(h)


if __name__ == "__main__":
    unittest.main()
