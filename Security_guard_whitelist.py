#!/usr/bin/env python3
"""Security Guard + IP-Whitelist: Admin-IPs und -Netze werden nie gezaehlt und nie gesperrt.

Erweitert den Core (Security_guard_core.py) ueber dessen ignore-Hook, ohne ihn zu kopieren.
"""
import ipaddress, os, sys
import Security_guard_core as core

DEFAULT_FILE = os.path.join(core.HERE, "whitelist.txt")


class Whitelist:
    """Einzelne IPs und CIDR-Netze aus einer Textdatei. Aenderungen gelten ohne Neustart."""

    def __init__(self, path=DEFAULT_FILE):
        self.path, self.mtime, self.networks = path, "nie geladen", []
        self.reload()

    def reload(self):
        try:
            st = os.stat(self.path)
            mtime = (st.st_mtime_ns, st.st_size)
        except OSError:
            mtime = None
        if mtime == self.mtime:  # Datei unveraendert: nichts zu tun
            return
        self.mtime, networks = mtime, []
        try:
            with open(self.path, encoding="utf-8") as f:
                for number, line in enumerate(f, 1):
                    entry = line.split("#", 1)[0].strip()  # Kommentare, auch am Zeilenende
                    if not entry:
                        continue
                    try:
                        networks.append(ipaddress.ip_network(entry, strict=False))
                    except ValueError:
                        core.log.warning("Whitelist Zeile %d ungueltig und uebersprungen: %r", number, entry)
        except OSError as e:
            core.log.warning("Whitelist '%s' nicht lesbar (%s) - nur Loopback ist geschuetzt", self.path, e)
        self.networks = networks
        core.log.info("Whitelist geladen: %d Eintraege aus %s", len(networks), self.path)

    def __contains__(self, ip):
        self.reload()
        addr = ipaddress.ip_address(ip)
        addr = getattr(addr, "ipv4_mapped", None) or addr  # ::ffff:10.0.0.5 zaehlt wie 10.0.0.5
        return addr.is_loopback or any(addr in net for net in self.networks)

    def __call__(self, ip):
        """ignore-Hook fuer den Core: True heisst 'nicht zaehlen, nicht sperren'."""
        if ip in self:
            core.log.info("[WHITELIST] %s steht auf der Whitelist - wird nicht gezaehlt", ip)
            return True
        return False


def main(argv=None):
    parser = core.build_parser()
    parser.add_argument("--whitelist", default=DEFAULT_FILE, help="Whitelist-Datei (Standard: whitelist.txt neben dem Skript)")
    args = parser.parse_args(argv)
    return core.run(args, ignore=Whitelist(args.whitelist))


if __name__ == "__main__":
    sys.exit(main())
