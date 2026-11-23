#!/usr/bin/env python3
"""Security Guard - Mini-SIEM/SOAR Core: erkennt Brute-Force-Logins und sperrt die Angreifer-IP.

Laeuft unveraendert auf Linux, macOS und Windows und nutzt nur die Python-Standardbibliothek.
"""
import argparse, ipaddress, logging, os, platform, re, shutil, subprocess, sys, time
from collections import defaultdict, deque

SYSTEM = platform.system()  # "Linux", "Darwin" (macOS) oder "Windows"
HERE = os.path.dirname(os.path.abspath(__file__))  # Dateien wie das Audit-Log liegen neben dem Skript
log = logging.getLogger("security_guard")

# Genau ein Treffer pro Fehlversuch: sshd meldet "Failed <methode> for ...", Windows Event 4625.
FAILURE = re.compile(r"Failed (?!publickey\b)\S+ for |EventID=4625")
IP_TOKEN = re.compile(r"\bfrom\s+\[?([0-9A-Fa-f:.]+)(?!\w)")

# Pro System ein Befehl, der neue Auth-Ereignisse als Textzeilen ausgibt.
# Windows: Security-Log alle 2 s abfragen, Properties[19] von Event 4625 ist die IP-Adresse.
SOURCES = {
    "Windows": ["powershell", "-NoProfile", "-Command",
                "$t=Get-Date; while($true){ Start-Sleep 2; $n=Get-Date; Get-WinEvent -FilterHashtable "
                "@{LogName='Security';Id=4625;StartTime=$t} -EA 0 | ForEach-Object "
                "{ 'EventID=4625 from ' + $_.Properties[19].Value }; $t=$n }"],
    "Darwin": ["log", "stream", "--style", "syslog", "--predicate", 'process BEGINSWITH "sshd"'],
    "Linux": ["journalctl", "-f", "-n", "0", "-o", "cat", "_COMM=sshd", "_COMM=sshd-session"],
}
LOG_FILES = ("/var/log/auth.log", "/var/log/secure")  # Linux mit klassischem Syslog


def parse(line):
    """Angreifer-IP eines fehlgeschlagenen Logins, sonst None."""
    if FAILURE.search(line):
        for token in reversed(IP_TOKEN.findall(line)):  # letzte IP zaehlt (Benutzer koennte "from" heissen)
            try:
                ip = ipaddress.ip_address(token.rstrip(".:"))
            except ValueError:
                continue
            return None if ip.is_loopback else str(ip)


class Guard:
    """Zaehlt Fehlversuche je IP im gleitenden Zeitfenster.

    Hooks fuer Module: block(ip) fuehrt die Sperre aus, ignore(ip) nimmt IPs von der Zaehlung aus.
    """

    def __init__(self, limit=3, window=60, block=lambda ip: True, ignore=lambda ip: False):
        self.limit, self.window, self.block, self.ignore = limit, window, block, ignore
        self.hits, self.blocked = defaultdict(deque), set()

    def feed(self, line, now=None):
        ip = parse(line)
        if ip is None or ip in self.blocked or self.ignore(ip):
            return None
        hits, now = self.hits[ip], time.monotonic() if now is None else now
        hits.append(now)
        while now - hits[0] >= self.window:
            hits.popleft()
        log.warning("Fehlgeschlagener Login von %s (%d/%d)", ip, len(hits), self.limit)
        if len(hits) >= self.limit:
            log.critical("[ALARM] Schwellenwert fuer %s ueberschritten - starte Eindaemmung", ip)
            del self.hits[ip]
            if self.block(ip):
                self.blocked.add(ip)
            return ip


def is_admin():
    return bool(__import__("ctypes").windll.shell32.IsUserAnAdmin()) if os.name == "nt" else os.geteuid() == 0


def firewall_command(ip, system=SYSTEM):
    if system == "Windows":
        return ["netsh", "advfirewall", "firewall", "add", "rule", f"name=SecurityGuard_{ip}", "dir=in", "action=block", f"remoteip={ip}"]
    if system == "Darwin":  # benoetigt in /etc/pf.conf: block drop in quick from <security_guard>
        return ["pfctl", "-t", "security_guard", "-T", "add", ip]
    if shutil.which("ufw"):  # prepend: muss vor bestehenden allow-Regeln stehen
        return ["ufw", "prepend", "deny", "from", ip]
    return ["ip6tables" if ":" in ip else "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]


def block_ip(ip, dry_run=False):
    cmd = firewall_command(ip)
    if os.name == "posix" and not is_admin() and shutil.which("sudo"):
        cmd = ["sudo", "-n", *cmd]  # -n: nie auf eine Passwortabfrage warten
    try:
        if not dry_run:
            subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        log.error("[FEHLER] Konnte %s nicht sperren: %s", ip, (getattr(e, "stderr", None) or str(e)).strip())
        return False
    log.critical("[%s] %s", "DRY-RUN" if dry_run else "CONTAINMENT", " ".join(cmd))
    return True


def follow(source, poll=1.0):
    """Neue Zeilen aus einem Befehl, stdin ("-") oder einer Datei - wie `tail -F`, inkl. Logrotation."""
    if isinstance(source, list):
        proc = subprocess.Popen(source, stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        yield from proc.stdout
        raise RuntimeError(f"Log-Quelle wurde beendet (Exit-Code {proc.wait()})")
    if source == "-":
        yield from sys.stdin
        return
    f = open(source, encoding="utf-8", errors="replace")
    f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        time.sleep(poll)
        st = os.stat(source) if os.path.exists(source) else None
        if st and (st.st_ino != os.fstat(f.fileno()).st_ino or st.st_size < f.tell()):  # rotiert/abgeschnitten
            f.close()
            f = open(source, encoding="utf-8", errors="replace")


def positive(value):
    if not value.isdigit() or int(value) < 1:
        raise argparse.ArgumentTypeError(f"muss eine positive ganze Zahl sein, nicht '{value}'")
    return int(value)


def build_parser():
    """Kommandozeile des Cores. Module ergaenzen hier eigene Optionen."""
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--log", help="Logdatei oder '-' fuer stdin (Standard: automatisch je Betriebssystem)")
    p.add_argument("--limit", type=positive, default=3, help="Fehlversuche bis zur Sperre (Standard: 3)")
    p.add_argument("--window", type=positive, default=60, help="Zeitfenster in Sekunden (Standard: 60)")
    p.add_argument("--audit", default=os.path.join(HERE, "incident_audit.log"), help="Audit-Logdatei (Standard: neben dem Skript)")
    p.add_argument("--dry-run", action="store_true", help="Nur melden, keine Firewall-Regel setzen")
    return p


def run(args, ignore=lambda ip: False):
    """Startet die Ueberwachung. Module uebergeben ihre Hooks als Argumente."""
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S",
                        handlers=[logging.StreamHandler(), logging.FileHandler(args.audit, encoding="utf-8")])
    source = args.log or next((p for p in LOG_FILES if os.path.exists(p)), SOURCES.get(SYSTEM, SOURCES["Linux"]))
    name = source if isinstance(source, str) else source[0]
    log.info("Security Guard aktiv | %s | Quelle: %s | %d Versuche in %ds%s", SYSTEM, name, args.limit,
             args.window, " | DRY-RUN" if args.dry_run else "")
    log.info("Audit-Log: %s", os.path.abspath(args.audit))
    if not is_admin():  # ohne Rechte liefert z. B. das Windows-Security-Log still keine Ereignisse
        log.warning("Keine Admin-/Root-Rechte: Log-Quelle evtl. unlesbar, Sperren evtl. nicht moeglich.")
    guard = Guard(args.limit, args.window, lambda ip: block_ip(ip, args.dry_run), ignore)
    try:
        for line in follow(source):
            guard.feed(line)
    except KeyboardInterrupt:
        log.info("Beendet.")
    except (OSError, RuntimeError) as e:
        log.error("[FEHLER] Log-Quelle '%s': %s (Admin-/Root-Rechte?)", name, e)
        return 1
    return 0


def main(argv=None):
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
