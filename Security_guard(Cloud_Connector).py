#!/usr/bin/env python3
import time
import re
import subprocess
import platform
import os
import sys
import json
import urllib.request
from collections import defaultdict
from datetime import datetime

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except ImportError:
    print("[-] Fehler: Tkinter konnte nicht geladen werden.")
    sys.exit(1)

# Globale Variablen für die Konfiguration
OS_TYPE = "Linux"
LOG_SOURCE_PATH = "/var/log/auth.log"
FAILED_ATTEMPT_LIMIT = 3
TIME_WINDOW = 60
AUDIT_LOG = "incident_audit.log"

failed_attempts = defaultdict(list)

CLOUD_WEBHOOK_URL = os.environ.get("SECURITY_GUARD_CLOUD_URL", "")
CLOUD_API_KEY = os.environ.get("SECURITY_GUARD_CLOUD_KEY", "")
CLOUD_TIMEOUT = 5

def send_to_cloud(event_type, message, ip_address=None):
    """Sendet strukturierte Security-Events plattformunabhängig per HTTPS an einen Cloud-Endpunkt."""
    if not CLOUD_WEBHOOK_URL:
        return

    payload = {
        "timestamp": datetime.now().isoformat(),
        "host": platform.node(),
        "os_type": OS_TYPE,
        "platform": platform.system(),
        "event_type": event_type,
        "ip_address": ip_address,
        "message": message,
    }

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SecurityGuard-Connector/1.0",
    }
    if CLOUD_API_KEY:
        headers["Authorization"] = f"Bearer {CLOUD_API_KEY}"

    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            CLOUD_WEBHOOK_URL,
            data=data,
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=CLOUD_TIMEOUT) as resp:
            if resp.status not in (200, 201, 202, 204):
                print(f"[-] Cloud-Connector unerwarteter Status: {resp.status}")
    except Exception as e:
        # Lokaler Betrieb darf durch Netzwerk-/Cloud-Ausfälle niemals blockiert werden
        print(f"[-] Cloud-Connector Fehler: {e}")

def open_config_dialog():
    """Öffnet das interaktive Tkinter-Konfigurationsfenster beim Start."""
    global OS_TYPE, LOG_SOURCE_PATH, FAILED_ATTEMPT_LIMIT
    
    root = tk.Tk()
    root.title("Security Guard - Core Setup")
    root.geometry("420x320")
    root.resizable(False, False)
    
    default_os = platform.system()
    if default_os not in ["Linux", "Windows"]:
        default_os = "Linux"
    
    default_path = "/var/log/auth.log" if default_os == "Linux" else "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"

    tk.Label(root, text="🛡️ Security Guard & Mini-SIEM Core", font=("Arial", 11, "bold")).pack(pady=10)

    # OS / Umgebungsauswahl
    tk.Label(root, text="Betriebssystem / Umgebung:").pack(anchor="w", padx=25)
    os_var = tk.StringVar(value=default_os)
    os_combobox = ttk.Combobox(root, textvariable=os_var, values=["Linux", "Windows", "WSL / Container"], state="readonly", width=38)
    os_combobox.pack(padx=25, pady=5)

    # Log-Pfad
    tk.Label(root, text="Log-Pfad (Datei oder Event-Quelle):").pack(anchor="w", padx=25)
    path_var = tk.StringVar(value=default_path)
    path_entry = tk.Entry(root, textvariable=path_var, width=40)
    path_entry.pack(padx=25, pady=5)

    # Schwellenwert
    tk.Label(root, text="Max. erlaubte Fehlversuche (Schwellenwert):").pack(anchor="w", padx=25)
    limit_var = tk.StringVar(value="3")
    limit_entry = tk.Entry(root, textvariable=limit_var, width=40)
    limit_entry.pack(padx=25, pady=5)

    def on_start():
        global OS_TYPE, LOG_SOURCE_PATH, FAILED_ATTEMPT_LIMIT
        try:
            val = int(limit_var.get())
            if val <= 0:
                raise ValueError
            FAILED_ATTEMPT_LIMIT = val
            OS_TYPE = os_var.get()
            LOG_SOURCE_PATH = path_var.get()
            root.destroy()
        except ValueError:
            messagebox.showerror("Ungültige Eingabe", "Bitte gib eine positive ganze Zahl für die Fehlversuche ein.")

    start_btn = tk.Button(root, text="Guard starten", command=on_start, bg="#1b5e20", fg="white", font=("Arial", 10, "bold"), width=25, height=2)
    start_btn.pack(pady=15)

    root.mainloop()

def log_audit(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{OS_TYPE}] {message}\n"
    print(log_entry.strip())
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"[-] Audit-Log Fehler: {e}")

    send_to_cloud(event_type="AUDIT", message=message)
    
def block_ip(ip_address):
    """Automatisierte Firewall-Eindämmung (SOAR) je nach Umgebung."""
    if "Linux" in OS_TYPE or "WSL" in OS_TYPE:
        command = ["sudo", "ufw", "deny", "from", ip_address]
    elif "Windows" in OS_TYPE:
        rule_name = f"SIEM_Block_{ip_address}"
        command = ["netsh", "advfirewall", "firewall", "add", "rule", 
                   f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"]
    else:
        log_audit(f"[FEHLER] Keine Firewall-Aktion für Umgebung {OS_TYPE} definiert.")
        return

    try:
        subprocess.run(command, captureoutput=True, text=True, check=True)
        log_audit(f"[CONTAINMENT] IP {ip_address} erfolgreich über Firewall gesperrt!")
    except subprocess.CalledProcessError as e:
        log_audit(f"[FEHLER] Konnte IP {ip_address} nicht sperren: {e.stderr.strip()}")

def monitor_logs():
    """Universeller Parser zur Log-Überwachung in Echtzeit."""
    log_audit(f"Starte Monitoring auf Ziel: {LOG_SOURCE_PATH}")
    
    if not os.path.exists(LOG_SOURCE_PATH):
        log_audit(f"[-] Pfad {LOG_SOURCE_PATH} nicht gefunden. Starte Simulations-/Wartemodus...")
        while True:
            time.sleep(5)
            log_audit(f"[SIMULATION] Warte auf Log-Einträge in {LOG_SOURCE_PATH}...")
        return

    with open(LOG_SOURCE_PATH, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            
            # Universal-Check für Fehlschläge
            if "Failed password" in line or "authentication failure" in line.lower() or "4625" in line:
                match = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
                if match:
                    handle_failed_login(match.group(1))

def handle_failed_login(ip):
    current_time = time.time()
    failed_attempts[ip] = [t for t in failed_attempts[ip] if current_time - t < TIME_WINDOW]
    failed_attempts[ip].append(current_time)
    
    attempt_count = len(failed_attempts[ip])
    log_audit(f"[WARNUNG] Fehlgeschlagener Login von IP: {ip} (Versuch {attempt_count}/{FAILED_ATTEMPT_LIMIT})")
    
    if attempt_count >= FAILED_ATTEMPT_LIMIT:
        log_audit(f"[ALARM] Schwellenwert für IP {ip} überschritten! Triggere SOAR-Eindämmung.")
        block_ip(ip)
        failed_attempts[ip] = []

if __name__ == "__main__":
    open_config_dialog()
    
    print(f"\n=== Security Guard Kernprozess aktiv ===")
    print(f"Modus: {OS_TYPE} | Log-Pfad: {LOG_SOURCE_PATH} | Schwellenwert: {FAILED_ATTEMPT_LIMIT}\n")
    
    monitor_logs()