"""Pestaña 2: Alertas IDS (Suricata) enriquecidas con MITRE ATT&CK y Threat Intel."""

import pandas as pd
import streamlit as st

from core import state
from core.config import CONFIG
from modules import suricata_reader
from ui.helpers import boton_exportar_csv


def render() -> None:
    st.header("Alertas IDS (Suricata)")
    st.caption(
        f"Leyendo en vivo: `{CONFIG['archivo_suricata']}` · "
        "enriquecido con MITRE ATT&CK y Threat Intelligence."
    )

    col_btn, col_grav, col_ip = st.columns([1, 2, 2])
    with col_btn:
        cargar_historico = st.button("📂 Cargar histórico completo")
    with col_grav:
        filtro_gravedad = st.multiselect(
            "Gravedad", options=[1, 2, 3], default=[1, 2, 3],
            format_func=lambda g: {1: "🔴 Alta", 2: "🟡 Media", 3: "🔵 Baja"}.get(g, str(g)),
        )
    with col_ip:
        filtro_ip = st.text_input("Filtrar por IP", placeholder="ej. 192.168.1.1")

    if cargar_historico:
        with st.spinner("Parseando eve.json completo..."):
            st.session_state["_alertas_historico"] = suricata_reader.leer_snapshot_completo()

    alertas_vivas = state.snapshot(state.alertas_ids, state.lock_alertas)
    alertas_historico = st.session_state.get("_alertas_historico", [])

    todas = alertas_historico + list(alertas_vivas)
    if not todas:
        st.success("Sin alertas. El tail en vivo está corriendo en segundo plano.")
        return

    df = pd.DataFrame(todas).drop_duplicates(subset=["Fecha/Hora", "IP Origen", "Firma"])

    if filtro_gravedad:
        df = df[df["Gravedad"].isin(filtro_gravedad)]
    if filtro_ip.strip():
        txt = filtro_ip.strip()
        df = df[
            df["IP Origen"].astype(str).str.contains(txt, na=False, regex=False)
            | df["IP Destino"].astype(str).str.contains(txt, na=False, regex=False)
        ]

    df = df.sort_values("Gravedad")

    m1, m2, m3 = st.columns(3)
    m1.metric("Alertas mostradas", len(df))
    m2.metric("Con técnica MITRE", int((df["MITRE Técnica"] != "").sum()) if "MITRE Técnica" in df.columns else 0)
    m3.metric(
        "IPs marcadas en Threat Intel",
        int(((df.get("TI Origen malicioso", "") != "") | (df.get("TI Destino malicioso", "") != "")).sum())
        if "TI Origen malicioso" in df.columns else 0,
    )

    if df.empty:
        st.info("Sin alertas que coincidan con los filtros.")
        return

    st.dataframe(df, width="stretch")
    boton_exportar_csv(df, "alertas_suricata.csv")
