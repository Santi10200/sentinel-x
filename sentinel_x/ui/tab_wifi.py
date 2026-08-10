"""Pestaña de inventario pasivo de seguridad Wi-Fi."""

import pandas as pd
import streamlit as st

from core import state
from core.config import CONFIG


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
    df.columns = ["SSID", "BSSID", "Cifrado", "PMF", "AKM", "Cifrados"][:len(df.columns)]
    st.dataframe(df.sort_values("SSID"), use_container_width=True)
