# 📘 Incident Response Playbook: SSH Brute-Force & Automated Containment

> **Language Notice:** This document is maintained in both English and German to align with international security engineering standards and local GRC frameworks (ISO 27001 / BSI IT-Grundschutz).

---

## Overview & Scope (English)

### 1. Purpose
This playbook defines the Standard Operating Procedure (SOP) for detecting, containing, and documenting unauthorized SSH access attempts (Brute-Force attacks) on Linux server infrastructure. Its main goal is to ensure a fast, structured, and repeatable incident response process.

### 2. Scope & Target Audience
- **Target Systems:** Linux-based servers running SSH services (Ubuntu/Debian).
- **Target Audience:** Blue Team operators, SOC analysts, System Administrators, and automated response scripts (SOAR).

### 3. Compliance & Framework Alignment
- **ISO/IEC 27001:2022:** 
  - *Control A.5.24* (Information Security Incident Management Planning and Preparation)
  - *Control A.8.16* (Monitoring Activities)
- **BSI IT-Grundschutz:**
  - *Baustein OPS.1.1.5* (Protokollierung / Logging)
  - *Baustein SYS.1.3* (Server unter Linux)

---

## Übersicht & Geltungsbereich (Deutsch)

### 1. Zweck
Dieses Playbook definiert die Standardarbeitsanweisung (SOP) zur Erkennung, Eindämmung und Dokumentation unbefugter SSH-Zugriffsversuche (Brute-Force-Angriffe) auf Linux-Serverinfrastrukturen. Ziel ist ein schneller, strukturierter und wiederholbarer Incident-Response-Prozess.

### 2. Geltungsbereich & Zielgruppe
- **Zielsysteme:** Linux-basierte Server mit aktivem SSH-Dienst (Ubuntu/Debian).
- **Zielgruppe:** Blue Team Operatoren, SOC-Analysten, Systemadministratoren sowie automatisierte Response-Skripte (SOAR).

### 3. Compliance & Standards-Referenz
- **ISO/IEC 27001:2022:**
  - *Control A.5.24* (Incident Management Planung & Vorbereitung)
  - *Control A.8.16* (Überwachungsaktivitäten / Monitoring)
- **BSI IT-Grundschutz:**
  - *Baustein OPS.1.1.5* (Protokollierung)
  - *Baustein SYS.1.3* (Server unter Linux)

---

## 🔄 Incident Lifecycle (Phasen-Übersicht / Phase Overview)


| 1. DETECT 🔍 | 2. CONTAIN 🛑 | 3. REPORT 📑 | 4. RECOVER 🔄 |
| :--- | :--- | :--- | :--- |
| **Log Analysis** | **Firewall Block** | **Audit Log & Alert** | **Review & Cleanup** |
| Real-time parsing of `/var/log/auth.log` | Automated IP block via `ufw` | Webhook notification & local audit file | Incident review & false-positive check |
