#!/usr/bin/env python3
"""Security Guard + GeoIP: ergaenzt Sperrmeldungen um Herkunftsland und Provider (Threat-Intelligence-Enrichment).

Erweitert den Core (Security_guard_core.py), indem es am Logger mithoert. Der Core bleibt unveraendert.
"""
import ipaddress, json, logging, sys, urllib.request
import Security_guard_core as core

API = "https://ipwho.is/{}"  # kostenlos, HTTPS, ohne API-Schluessel
ENRICH = {"blocked", "block_failed"}  # erst sperren, dann nachschlagen: die Abfrage verzoegert nie die Sperre
CACHE = {}  # IP -> Herkunft, damit jede IP nur einmal nachgeschlagen wird


def lookup(ip, timeout=3):
    """'Land (Code), Provider, AS-Nummer' einer oeffentlichen IP."""
    if not ipaddress.ip_address(ip).is_global:  # private/reservierte Adressen verlassen nie das Netz
        return "nicht-oeffentliches Netz"
    if ip not in CACHE:
        try:
            request = urllib.request.Request(API.format(ip), headers={"User-Agent": "SecurityGuard"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.load(response)
        except (OSError, ValueError) as e:  # offline, Zeitueberschreitung, kaputte Antwort
            core.log.warning("GeoIP-Abfrage fuer %s fehlgeschlagen: %s", ip, e)
            return "unbekannt (GeoIP nicht erreichbar)"  # bewusst nicht cachen: spaeter neu versuchen
        if not data.get("success"):
            return "unbekannt"
        net = data.get("connection") or {}
        CACHE[ip] = f"{data.get('country', '?')} ({data.get('country_code', '?')}), {net.get('org') or net.get('isp') or '?'}, AS{net.get('asn', '?')}"
    return CACHE[ip]


class GeoIP(logging.Filter):
    """Haengt die Herkunft an Sperrmeldungen an. Sie steht damit im Audit-Log und ist fuer alle Module sichtbar."""

    def filter(self, record):
        if getattr(record, "event", None) in ENRICH:
            record.origin = lookup(record.ip)
            record.msg, record.args = f"{record.msg} | Herkunft: %s", (*record.args, record.origin)
        return True


def main(argv=None):
    core.log.addFilter(GeoIP())
    return core.run(core.build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
