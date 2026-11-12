# 🛡️ Cross-Platform Security Guard & Automated SIEM/SOAR

> *Lightweight cross-platform Python Mini-SIEM & SOAR prototype featuring an interactive Tkinter setup GUI, real-time log monitoring, automated firewall containment (UFW/Netsh), and ISO 27001/BSI compliance.*
> 
> *Ein leichtgewichtiger, plattformübergreifender Python Mini-SIEM- & SOAR-Prototyp mit interaktivem Tkinter-Setup-GUI, Echtzeit-Log-Überwachung, automatisierter Firewall-Eindämmung (UFW/Netsh) und ISO 27001/BSI-konformen Incident Response.*

---

## 🚀 Features (Funktionen)
- **Cross-Platform Support:** Runs natively on Linux, Windows, and sub-systems (WSL / Containers) / *Läuft nativ auf Linux, Windows und WSL/Containern.*
- **Interactive Tkinter Setup GUI:** Start-up configuration popup to dynamically set OS, log path, and threshold limits / *Startbegleitendes Pop-up zur dynamischen Konfiguration von Betriebssystem, Log-Pfad und Schwellenwerten.*
- **Real-Time Log Monitoring:** Parses system logs live via regex / *Überwacht Log-Dateien (Linux Auth-Logs oder Windows-Ereignisquellen) in Echtzeit.*
- **Automated Containment (SOAR):** Instantly blocks malicious IP addresses via Linux UFW or Windows Firewall (`netsh`) / *Sofortige IP-Sperrung über UFW oder Windows Firewall.*
- **Audit & Alerting:** Generates tamper-resistant local audit logs (`incident_audit.log`) and optional webhooks / *Revisionssicheres Audit-Logging und optionale Webhooks.*

---

## 📋 Compliance & Frameworks
- **ISO 27001 (Control A.16):** Covers Information Security Incident Management and automated containment.
- **BSI IT-Grundschutz (OPS.1.1.5 & SYS.1.3):** Structured logging and early threat detection on Linux and Windows server systems.

---

## ⚙️ Quickstart (Schnellstart)

1. Clone the repository / Repository klonen:
   ```bash
   git clone [https://github.com/DEIN-BENUTZERNAME/linux-security-guard-SIEM.git](https://github.com/DEIN-BENUTZERNAME/linux-security-guard-SIEM.git)
   cd linux-security-guard-SIEM

---

## 🧩 Planned / Easy-to-Integrate Modules (Erweiterungsmodule)

To demonstrate scalability and advanced engineering, the following modules can be easily plugged into the core engine:(Um Skalierbarkeit zu zeigen, lässt sich das System unkompliziert um folgende Module erweitern:)

🗄️ Database Integration (SQLite):

Storing historical incident data and attacker metadata in a local database instead of volatile memory.

🌍 GeoIP Enrichment:

Using geoip2 to automatically resolve the attacker's country of origin during the alert phase.

⏱️ Dynamic IP Whitelisting:

Implementaion an automated safe-list for administrative IPs to prevent self-lockouts.

📊 Web Dashboard (Streamlit / Flask):

Building a lightweight local web interface to visualize blocked IPs and attack frequencies over time.

☁️ Cloud SIEM Connector (Azure / Microsoft Sentinel):

Forward structured events via API to cloud storage or log analytics workspaces (SC-900 alignment).

---

## 📄 Documentation / Dokumentation

Check out the INCIDENT_PLAYBOOK.md for detailed standard operating procedures (SOP) regarding incident handling.    
