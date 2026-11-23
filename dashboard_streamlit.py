#!/usr/bin/env python3
"""Security Guard - Streamlit-Dashboard: das Lagebild mit dem wenigsten Code.

Liest ueber dashboard_data.py die SQLite-Datenbank und aktualisiert sich alle 2 Sekunden.
Start: py -m streamlit run dashboard_streamlit.py   (andere Datenbank: ... -- --db pfad\\zur.db)
Sicherheit und Telemetrie stehen in .streamlit/config.toml (nur 127.0.0.1, keine Nutzungsstatistik).
"""
import argparse, os
from datetime import datetime
import streamlit as st
import dashboard_data as data

LABELS = {"failed": "Fehlversuche", "alert": "Alarme", "blocked": "Sperren", "block_failed": "Sperre fehlgeschlagen"}
TIME = st.column_config.DatetimeColumn  # ISO-Zeitstempel lesbar anzeigen

parser = argparse.ArgumentParser()
parser.add_argument("--db", default=os.environ.get("SECURITY_GUARD_DB", data.DEFAULT_DB))
DB = parser.parse_known_args()[0].db

st.set_page_config(page_title="Security Guard - Lagebild", layout="wide")
st.title("Security Guard - Lagebild")


@st.fragment(run_every="2s")  # nur dieser Teil wird neu gezeichnet, nicht die ganze Seite
def lagebild():
    snap = data.snapshot(DB)
    if snap["error"]:
        st.warning(snap["error"])
    for column, (event, label) in zip(st.columns(4), LABELS.items()):
        column.metric(label, snap["counts"][event])

    left, right = st.columns(2)
    left.subheader("Top-Angreifer")
    left.dataframe([{**row, "origin": row["origin"] or ""} for row in snap["top"]], hide_index=True, width="stretch", column_config={
        "ip": "IP", "attempts": "Versuche", "last_seen": TIME("zuletzt", format="YYYY-MM-DD HH:mm:ss"), "origin": "Herkunft"})
    right.subheader("Fehlversuche pro Stunde")
    if snap["per_hour"]:
        right.bar_chart({r["hour"][-2:] + "h": r["attempts"] for r in snap["per_hour"]}, x_label="Stunde", y_label="Fehlversuche")
    else:
        right.caption("noch keine Fehlversuche")

    st.subheader("Letzte Ereignisse")
    st.dataframe(snap["recent"], hide_index=True, width="stretch", column_config={
        "timestamp": TIME("Zeit", format="YYYY-MM-DD HH:mm:ss"), "event": "Ereignis", "ip": "IP", "message": "Meldung"})
    st.caption(f"{DB}  |  aktualisiert {datetime.now():%H:%M:%S}")


lagebild()
