"""Pestaña de inventario pasivo de seguridad Wi-Fi."""

import pandas as pd
import plotly.express as px
import streamlit as st

from core import state
from core.config import CONFIG
from modules import postura
from ui.helpers import badge_severidad

_ORDEN = ["Crítica", "Alta", "Media", "Baja"]


def render() -> None:
    st.header("Seguridad Wi-Fi (captura pasiva)")
    iface = CONFIG["wifi_monitor_iface"]
    if not iface:
        st.info("Configura una interfaz monitor con SENTINEL_WIFI_MONITOR_IFACE=wlan0mon.")
        return
    st.caption(f"Escuchando beacons y probe responses en `{iface}`. No se transmiten paquetes.")
    redes = state.snapshot_dict(state.redes_wifi, state.lock_redes_wifi)
    if not redes:
        st.caption("Esperando tramas 802.11. Verifica modo monitor y canal.")
        return
    df = pd.DataFrame(redes.values())
    columnas = ["ssid", "bssid", "cifrado", "pmf", "akm_suites", "cipher_suites"]
    df = df[[c for c in columnas if c in df.columns]].copy()
    for columna in ("akm_suites", "cipher_suites"):
        if columna in df.columns:
            df[columna] = df[columna].apply(lambda v: ", ".join(v) if isinstance(v, list) else v)
    nombres = {"ssid": "SSID", "bssid": "BSSID", "cifrado": "Cifrado", "pmf": "PMF",
               "akm_suites": "AKM", "cipher_suites": "Cifrados"}
    df = df.rename(columns=nombres)

    hallazgos = postura.wifi_debil(list(redes.values()))
    peor_por_red: dict[str, str] = {}
    for h in hallazgos:
        bssid = h["Activo"].rsplit("(", 1)[-1].rstrip(")")
        actual = peor_por_red.get(bssid)
        if actual is None or _ORDEN.index(h["Severidad"]) < _ORDEN.index(actual):
            peor_por_red[bssid] = h["Severidad"]
    df.insert(0, "Riesgo", df["BSSID"].map(lambda b: badge_severidad(peor_por_red[b]) if b in peor_por_red else "🟢 OK"))

    m1, m2, m3 = st.columns(3)
    m1.metric("Redes observadas", len(df))
    m2.metric("Con cifrado débil o abiertas", sum(1 for s in peor_por_red.values() if s in ("Crítica", "Alta")))
    m3.metric("Sin PMF obligatorio", sum(1 for h in hallazgos if h["Categoría"] == "Wi-Fi sin PMF obligatorio"))

    fig = px.histogram(df, x="Cifrado", color="Cifrado", height=260, title="Redes por tipo de cifrado")
    fig.update_layout(showlegend=False, margin=dict(t=50, b=10))
    st.plotly_chart(fig, width="stretch")
    st.dataframe(df.sort_values("SSID"), width="stretch", hide_index=True)

    if hallazgos:
        st.markdown("#### Recomendaciones (NIST CSF PR.DS-02 · PR.IR-01)")
        st.dataframe(pd.DataFrame(hallazgos), width="stretch", hide_index=True)
