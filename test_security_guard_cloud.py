"""Tests fuer den Cloud-Connector mit einem lokalen Test-Webhook. Ausfuehren: python -m unittest -v"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

import Security_guard_core as core
import Security_guard_cloud as cloud

HERE = os.path.dirname(os.path.abspath(__file__))
LINE = "Failed password for root from 203.0.113.5 port 22 ssh2"


class Webhook:
    """Kleiner HTTP-Server auf 127.0.0.1, der empfangene Ereignisse sammelt."""

    def __init__(self, delay=0):
        received = self.received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                time.sleep(delay)
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.append((dict(self.headers), body))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/events"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class ConnectorTest(unittest.TestCase):
    def setUp(self):
        self.addCleanup(setattr, core.log, "propagate", core.log.propagate)
        core.log.propagate = False  # keine Konsolenausgabe im Test
        self.handlers = list(core.log.handlers)
        self.addCleanup(lambda: setattr(core.log, "handlers", self.handlers))

    def connect(self, webhook, **options):
        listener = cloud.attach(webhook.url, "geheim", **options)
        self.addCleanup(webhook.close)
        return listener

    def test_events_arrive_as_json_with_key(self):
        hook = Webhook()
        listener = self.connect(hook)
        guard = core.Guard(2, 60, lambda ip: core.block_ip(ip, dry_run=True))
        guard.feed(LINE, 0)
        guard.feed(LINE, 1)
        core.log.warning("Statusmeldung ohne Ereignis")
        listener.stop()
        self.assertEqual([body["event"] for _, body in hook.received], ["failed", "failed", "alert", "blocked"])
        headers, body = hook.received[-1]
        self.assertEqual(headers["Authorization"], "Bearer geheim")
        self.assertEqual(body["ip"], "203.0.113.5")
        self.assertEqual(body["system"], core.SYSTEM)
        self.assertRegex(body["timestamp"], r"[+-]\d\d:\d\d$")  # mit Zeitzone

    def test_slow_cloud_never_slows_down_the_guard(self):
        listener = self.connect(Webhook(delay=1))
        guard = core.Guard(3, 60)
        start = time.monotonic()
        for t in range(3):
            guard.feed(LINE, t)
        self.assertLess(time.monotonic() - start, 0.5)
        listener.stop()

    def test_unreachable_cloud_is_reported_not_raised(self):
        with socket.socket() as s:  # freien Port finden, auf dem garantiert niemand lauscht
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        handler = cloud.Cloud(f"http://127.0.0.1:{port}/", retries=2, timeout=1)
        record = core.log.makeRecord("security_guard", 30, "", 0, "x", (), None, extra=core.event("failed", "1.2.3.4")["extra"])
        core.log.propagate = True
        with mock.patch.object(cloud.time, "sleep"), self.assertLogs("security_guard", "WARNING") as logs:
            handler.emit(record)
        self.assertIn("nach 2 Versuchen verworfen", logs.output[0])

    def test_full_outbox_drops_instead_of_blocking(self):
        outbox = cloud.Outbox(cloud.queue.Queue(1))
        record = core.log.makeRecord("security_guard", 30, "", 0, "x", (), None, extra=core.event("failed", "1.2.3.4")["extra"])
        outbox.handle(record)
        outbox.handle(record)  # zweites Ereignis passt nicht mehr hinein
        self.assertEqual(outbox.queue.qsize(), 1)


class UrlTest(unittest.TestCase):
    def test_only_https_or_localhost(self):
        self.assertEqual(cloud.check_url("https://siem.example.com/x"), "https://siem.example.com/x")
        self.assertEqual(cloud.check_url("http://localhost:8080/x"), "http://localhost:8080/x")
        for url in ("http://siem.example.com/x", "ftp://example.com", "siem.example.com"):
            with self.assertRaises(ValueError, msg=url):
                cloud.check_url(url)

    def test_missing_or_insecure_url_is_rejected_at_start(self):
        env = {k: v for k, v in os.environ.items() if k != cloud.URL_ENV}
        script = os.path.join(HERE, "Security_guard_cloud.py")
        r = subprocess.run([sys.executable, script], capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("keine Cloud-URL", r.stderr)
        r = subprocess.run([sys.executable, script, "--cloud-url", "http://siem.example.com"],
                           capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("https://", r.stderr)


class EndToEndTest(unittest.TestCase):
    def test_dry_run_sends_to_webhook(self):
        hook = Webhook()
        self.addCleanup(hook.close)
        folder = tempfile.mkdtemp()
        env = dict(os.environ, **{cloud.KEY_ENV: "e2e-key"})
        r = subprocess.run([sys.executable, os.path.join(HERE, "Security_guard_cloud.py"), "--log", "-", "--dry-run",
                            "--cloud-url", hook.url, "--audit", os.path.join(folder, "audit.log")],
                           input=(LINE + "\n") * 3, capture_output=True, text=True, timeout=30, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([b["event"] for _, b in hook.received], ["failed", "failed", "failed", "alert", "blocked"])
        self.assertEqual(hook.received[0][0]["Authorization"], "Bearer e2e-key")


if __name__ == "__main__":
    unittest.main()
