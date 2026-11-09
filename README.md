# 🛡️ Linux Security Guard & Automated SIEM/SOAR

> *Lightweight Python Mini-SIEM & SOAR prototype for real-time SSH brute-force detection, automated UFW firewall containment, and ISO 27001/BSI incident response.*
> 
> *Ein leichtgewichtiger Python Mini-SIEM- & SOAR-Prototyp zur Echtzeit-Erkennung von SSH-Brute-Force-Angriffen, automatisierter UFW-Firewall-Eindämmung und ISO 27001/BSI-konformen Incident Response.*

---

## 🚀 Features (Funktionen)
- **Real-Time Log Monitoring:** Parses Linux system logs (`/var/log/auth.log`) live.
- **Threat Detection:** Detects rapid failed SSH login attempts (Brute-Force heuristic).
- **Automated Containment (SOAR):** Instantly blocks malicious IP addresses via Linux UFW.
- **Audit & Alerting:** Generates tamper-resistant local audit logs and optional webhooks (Discord/Teams).

---

## 📋 Compliance & Frameworks
- **ISO 27001 (Control A.16):** Covers Information Security Incident Management and automated containment.
- **BSI IT-Grundschutz (OPS.1.1.5 & SYS.1.3):** Structured logging and early threat detection on Linux server systems.

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
