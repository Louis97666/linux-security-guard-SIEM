#!/usr/bin/env python3
"""Security Guard + Cloud-Connector: leitet jedes Ereignis als JSON per HTTPS an ein Cloud-SIEM weiter.

Ziel ist ein beliebiger Webhook, z. B. Azure Logic App (Sentinel), Splunk oder Elastic. Gesendet wird in
einem eigenen Thread: Ein langsamer oder ausgefallener Endpunkt bremst Erkennung und Sperre nie.
"""
import json, logging, logging.handlers, os, platform, queue, sys, time, urllib.parse, urllib.request
from datetime import datetime
import Security_guard_core as core

URL_ENV, KEY_ENV = "SECURITY_GUARD_CLOUD_URL", "SECURITY_GUARD_CLOUD_KEY"  # Schluessel nie in Code oder Kommandozeile


def check_url(url):
    """Nur HTTPS, sonst ginge der API-Schluessel im Klartext uebers Netz. Ausnahme: localhost zum Testen."""
    parts = urllib.parse.urlparse(url)
    if parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")):
        return url
    raise ValueError(f"Cloud-URL muss mit https:// beginnen: {url}")


class Cloud(logging.Handler):
    """Sendet ein Ereignis als JSON-POST, mit bis zu drei Versuchen. Laeuft im Hintergrund-Thread."""

    def __init__(self, url, key=None, timeout=5, retries=3):
        super().__init__()
        self.url, self.timeout, self.retries = check_url(url), timeout, retries
        self.headers = {"Content-Type": "application/json", "User-Agent": "SecurityGuard"}
        if key:
            self.headers["Authorization"] = f"Bearer {key}"

    def emit(self, record):
        body = json.dumps({
            "timestamp": datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="seconds"),
            "host": platform.node(), "system": core.SYSTEM, "event": record.event, "ip": record.ip,
            "message": record.getMessage(), "origin": getattr(record, "origin", None)}).encode()
        for attempt in range(1, self.retries + 1):
            try:
                request = urllib.request.Request(self.url, body, self.headers, method="POST")
                urllib.request.urlopen(request, timeout=self.timeout).close()
                return
            except OSError as e:  # Netzwerkfehler, Zeitueberschreitung, HTTP 4xx/5xx
                if attempt == self.retries:
                    core.log.warning("[CLOUD] Ereignis nach %d Versuchen verworfen: %s", attempt, e)
                else:
                    time.sleep(attempt)  # 1 s, 2 s, ... warten, dann erneut


class Outbox(logging.handlers.QueueHandler):
    """Legt Ereignisse in die Warteschlange. Ist sie voll, weil die Cloud lange weg ist, wird verworfen statt blockiert."""

    def enqueue(self, record):
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            pass


def attach(url, key=None, maxsize=1000, **options):
    """Haengt den Connector an den Core. stop() am Rueckgabewert stellt noch wartende Ereignisse zu."""
    outbox = Outbox(queue.Queue(maxsize))  # begrenzt: der Speicher waechst bei einem Ausfall nicht endlos
    outbox.addFilter(lambda record: hasattr(record, "event"))  # nur Ereignisse, keine Statusmeldungen
    listener = logging.handlers.QueueListener(outbox.queue, Cloud(url, key, **options))
    core.log.addHandler(outbox)
    listener.start()
    return listener


def main(argv=None):
    parser = core.build_parser()
    parser.add_argument("--cloud-url", default=os.environ.get(URL_ENV), help=f"Webhook-URL (oder Umgebungsvariable {URL_ENV})")
    args = parser.parse_args(argv)
    if not args.cloud_url:
        parser.error(f"keine Cloud-URL: --cloud-url angeben oder {URL_ENV} setzen")
    try:
        listener = attach(args.cloud_url, os.environ.get(KEY_ENV))
    except ValueError as e:
        parser.error(str(e))
    try:
        return core.run(args)
    finally:
        listener.stop()


if __name__ == "__main__":
    sys.exit(main())
