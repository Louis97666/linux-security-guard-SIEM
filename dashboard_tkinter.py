#!/usr/bin/env python3
"""Security Guard - Tkinter-Dashboard: Live-Lagebild ohne Installation und ohne Internet.

Liest ueber dashboard_data.py die SQLite-Datenbank und aktualisiert sich alle 2 Sekunden.
Start: py dashboard_tkinter.py   (vorher fuer eine Vorfuehrung: py dashboard_data.py --demo)
"""
import argparse, tkinter as tk
from datetime import datetime
from tkinter import ttk
import dashboard_data as data

C = {"bg": "#10151c", "panel": "#18202a", "line": "#2a323e", "fg": "#e4e8ef", "muted": "#98a2b3", "accent": "#7d9ef5",
     "failed": "#f0b56a", "alert": "#f2857b", "blocked": "#6fcf97", "block_failed": "#d19bf5"}
LABELS = {"failed": "Fehlversuche", "alert": "Alarme", "blocked": "Sperren", "block_failed": "Sperre fehlgeschlagen"}
REFRESH_MS = 2000


class Dashboard(tk.Tk):
    def __init__(self, db=data.DEFAULT_DB):
        super().__init__()
        self.db, self.per_hour = db, []
        self.title("Security Guard - Lagebild")
        self.geometry("1100x700")
        self.configure(bg=C["bg"], padx=16, pady=12)
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["fg"], rowheight=24, borderwidth=0)
        style.configure("Treeview.Heading", background=C["bg"], foreground=C["muted"], relief="flat")
        style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])  # ohne hellen Rahmen
        self.columnconfigure((0, 1), weight=1, uniform="half")
        self.rowconfigure((2, 4), weight=1)

        tk.Label(self, text="Security Guard - Lagebild", font=("Segoe UI", 18, "bold"), bg=C["bg"], fg=C["fg"]).grid(row=0, column=0, sticky="w")
        self.status = tk.Label(self, anchor="e", bg=C["bg"], fg=C["muted"])
        self.status.grid(row=0, column=1, sticky="e")

        tiles = tk.Frame(self, bg=C["bg"])
        tiles.grid(row=1, column=0, columnspan=2, sticky="ew", pady=12)
        self.tiles = {}
        for i, (event, label) in enumerate(LABELS.items()):
            tiles.columnconfigure(i, weight=1, uniform="tile")
            box = tk.Frame(tiles, bg=C["panel"], padx=14, pady=10, highlightthickness=1, highlightbackground=C["line"])
            box.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0))
            tk.Label(box, text=label, bg=C["panel"], fg=C["muted"]).pack(anchor="w")
            self.tiles[event] = tk.Label(box, text="0", font=("Consolas", 26, "bold"), bg=C["panel"], fg=C[event])
            self.tiles[event].pack(anchor="w")

        self.top = self.table(2, 0, "Top-Angreifer", {"ip": 140, "attempts": 80, "last_seen": 160, "origin": 160},
                              {"ip": "IP", "attempts": "Versuche", "last_seen": "zuletzt", "origin": "Herkunft"})
        chart_box = self.panel(2, 1, "Fehlversuche pro Stunde")
        self.chart = tk.Canvas(chart_box, bg=C["panel"], highlightthickness=0, height=200)
        self.chart.pack(fill="both", expand=True)
        self.chart.bind("<Configure>", lambda _: self.draw_chart())
        self.recent = self.table(4, 0, "Letzte Ereignisse", {"timestamp": 160, "event": 110, "ip": 140, "message": 560},
                                 {"timestamp": "Zeit", "event": "Ereignis", "ip": "IP", "message": "Meldung"}, span=2)
        for event in LABELS:
            self.recent.tag_configure(event, foreground=C[event])

    def panel(self, row, col, title, span=1):
        box = tk.Frame(self, bg=C["panel"], padx=10, pady=8, highlightthickness=1, highlightbackground=C["line"])
        box.grid(row=row, column=col, columnspan=span, sticky="nsew", padx=(0 if col == 0 else 8, 0), pady=(0, 12))
        tk.Label(box, text=title, font=("Segoe UI", 11, "bold"), bg=C["panel"], fg=C["fg"]).pack(anchor="w", pady=(0, 6))
        return box

    def table(self, row, col, title, widths, headings, span=1):
        tree = ttk.Treeview(self.panel(row, col, title, span), columns=list(widths), show="headings", height=6)
        for key, width in widths.items():
            tree.heading(key, text=headings[key], anchor="w")
            tree.column(key, width=width, anchor="w", stretch=key == list(widths)[-1])
        tree.pack(fill="both", expand=True)
        return tree

    def render(self, snap):
        """Zeichnet einen Datenstand aus dashboard_data.snapshot()."""
        for event, label in self.tiles.items():
            label.config(text=str(snap["counts"].get(event, 0)))
        for tree, rows in ((self.top, snap["top"]), (self.recent, snap["recent"])):
            tree.delete(*tree.get_children())
            for row in rows:
                values = [str(row.get(c) or "").replace("T", " ", 1) if c in ("timestamp", "last_seen") else row.get(c) or ""
                          for c in tree["columns"]]
                tree.insert("", "end", values=values, tags=(row.get("event", ""),))
        self.per_hour = snap["per_hour"]
        self.draw_chart()
        self.status.config(text=snap["error"] or f"{self.db}  |  aktualisiert {datetime.now():%H:%M:%S}",
                           fg=C["alert"] if snap["error"] else C["muted"])

    def draw_chart(self):
        c, rows = self.chart, self.per_hour
        c.delete("all")
        w, h, pad = c.winfo_width(), c.winfo_height(), 24
        if not rows or w < 50:
            c.create_text(w / 2, h / 2, text="noch keine Fehlversuche", fill=C["muted"])
            return
        peak, slot = max(r["attempts"] for r in rows), (w - 2 * pad) / len(rows)
        for i, r in enumerate(rows):
            x, top = pad + i * slot, h - pad - (h - 2 * pad) * r["attempts"] / peak
            c.create_rectangle(x + slot * 0.15, top, x + slot * 0.85, h - pad, fill=C["accent"], width=0)
            c.create_text(x + slot / 2, top - 8, text=r["attempts"], fill=C["fg"], font=("Consolas", 9))
            c.create_text(x + slot / 2, h - pad + 10, text=r["hour"][-2:] + "h", fill=C["muted"], font=("Consolas", 8))

    def refresh(self):
        self.render(data.snapshot(self.db))
        self.after(REFRESH_MS, self.refresh)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tkinter-Dashboard des Security Guard")
    parser.add_argument("--db", default=data.DEFAULT_DB, help="SQLite-Datei des Guard (Standard: neben dem Skript)")
    app = Dashboard(parser.parse_args().db)
    app.refresh()
    app.mainloop()
