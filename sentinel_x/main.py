"""
Sentinel-X v2: Plataforma unificada de monitoreo de seguridad de red.
=======================================================================

Arquitectura en 5 capas (ver README.md para el diagrama completo):

  1. Captura     -> modules/sniffer.py, suricata_reader.py, zeek_reader.py
  2. Enriquecimiento -> modules/tls_analysis.py, device_profiler.py, threat_intel.py
  3. Análisis    -> modules/beaconing.py, lateral_movement.py, ml_baseline.py, postura.py
  4. Correlación y presentación -> modules/correlation_engine.py, analisis.py, ui/*
  5. Gobierno y respuesta -> modules/nist_csf.py, respuesta_incidentes.py, informe.py

Todo el estado compartido entre hilos vive en core/state.py (nunca en
st.session_state) para evitar deadlocks y duplicación de hilos en cada
rerun de Streamlit. core/orchestrator.py garantiza que los hilos de
fondo se lancen una sola vez por proceso.

Para ejecutar:
    sudo streamlit run main.py

(sudo es necesario para ARP scan, sniffing de paquetes y nmap -O)
"""

import streamlit as st

from core.config import CONFIG
from core.logger import get_logger
from core.network_iface import interfaz_configurada, cidr_de_interfaz, ip_y_mascara
from core.orchestrator import arrancar_todo
from core import database
from ui.helpers import estado_hilo_widget
from ui import (
    tab_resumen, tab_nist, tab_incidentes, tab_alertas, tab_dispositivos,
    tab_tls, tab_lateral, tab_avanzado, tab_wifi,
)

logger = get_logger("main")

st.set_page_config(page_title="Sentinel-X v2", layout="wide", page_icon="🛡️")

# ── Arranque único de hilos de fondo ─────────────────────────────────────
_iface = interfaz_configurada()
_cidr_lan = cidr_de_interfaz(_iface)
arrancar_todo(cidr_lan=_cidr_lan)

# ── Mantenimiento periódico de la base de datos ──────────────────────────
if "_db_rotada" not in st.session_state:
    database.rotar_si_excede_limite()
    st.session_state["_db_rotada"] = True

# ── Sidebar: estado del sistema ──────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Estado del sistema")

    info_iface = ip_y_mascara(_iface)
    ip_actual = info_iface[0] if info_iface else "sin IP"
    st.caption(f"Interfaz: `{_iface}` · `{ip_actual}`")
    if _cidr_lan:
        st.caption(f"Red local: `{_cidr_lan}`")

    estado_hilo_widget("sniffer_tls", "Sniffer TLS")
    estado_hilo_widget("sniffer_lan", "Sniffer LAN")
    estado_hilo_widget("sniffer_identidad", "Identidad (DHCP/mDNS/SSDP)")
    estado_hilo_widget("suricata_tail", "Suricata (tail)")
    estado_hilo_widget("zeek_watch", "Zeek (watch)")
    estado_hilo_widget("ti_updater", "Threat Intel")
    estado_hilo_widget("ml_baseline", "Baseline ML")
    if CONFIG["wifi_monitor_iface"]:
        estado_hilo_widget("sniffer_wifi", "Sniffer Wi-Fi")

    st.markdown("---")
    auto_refresh = st.toggle("Auto-refresco del dashboard", value=False)
    refresh_seg = st.slider(
        "Intervalo (segundos)", 3, 30, CONFIG["auto_refresh_seg_default"],
        disabled=not auto_refresh,
    )

    st.markdown("---")
    st.caption("Sentinel-X v2 · Laboratorio personal")

# ── Cuerpo principal ──────────────────────────────────────────────────────
st.title("🛡️ Sentinel-X v2: Centro Unificado de Seguridad")
st.markdown(
    "Captura, enriquecimiento, análisis y correlación de eventos de red en una sola plataforma."
)

# Orden pensado para el flujo NIST: visión general -> perfil CSF -> detección y
# respuesta -> vistas de detalle por sensor.
_PESTANAS = [
    ("📊 Resumen", tab_resumen),
    ("🏛️ NIST CSF", tab_nist),
    ("🧩 Incidentes", tab_incidentes),
    ("🚦 Alertas IDS", tab_alertas),
    ("🔍 Dispositivos", tab_dispositivos),
    ("📡 TLS / JA3", tab_tls),
    ("↔️ Mov. lateral", tab_lateral),
    ("📶 Wi-Fi", tab_wifi),
    ("🧠 ML / Zeek / TI", tab_avanzado),
]

for pestana, (_, modulo) in zip(st.tabs([nombre for nombre, _ in _PESTANAS]), _PESTANAS):
    with pestana:
        modulo.render()

# ── Auto-refresco ─────────────────────────────────────────────────────────
if auto_refresh:
    import time
    time.sleep(refresh_seg)
    st.rerun()
