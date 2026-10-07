"""Centro de operaciones del sensor: salud, capacidad y acciones de recuperación."""

import pandas as pd
import streamlit as st

from modules import sensor_health


def _badge(estado: str) -> str:
    return {"Operativo": "🟢", "Atención": "🟡", "Crítico": "🔴"}.get(estado, "⚪") + f" {estado}"


def render() -> None:
    st.header("Operación del sensor")
    st.caption("Estado de las fuentes de detección, frescura de telemetría y capacidad local.")
    datos = sensor_health.resumen()
    c1, c2, c3 = st.columns(3)
    c1.metric("Estado global", _badge(datos["estado_global"]))
    c2.metric("Base local", f"{datos['db_mb']:.2f} / {datos['db_limite_mb']} MB")
    c3.metric("Tiempo activo", f"{int(datos['uptime_seg'] // 60)} min")

    fuentes = pd.DataFrame(datos["fuentes"])
    st.subheader("Fuentes y detectores")
    st.dataframe(fuentes, use_container_width=True, hide_index=True)

    capacidad = pd.DataFrame(datos["capacidad"])
    st.subheader("Buffers en memoria")
    st.dataframe(capacidad, use_container_width=True, hide_index=True)
    if not capacidad.empty and (capacidad["Uso (%)"] >= 80).any():
        st.warning("Un buffer supera el 80 %. Aumenta SENTINEL_MAX_* o reduce la retención/volumen.")

    with st.expander("Guía de operación", expanded=False):
        st.markdown(
            "- **Error/Detenido:** revisa permisos de captura, interfaz y servicio de origen.\n"
            "- **Sin actividad:** la fuente funciona, pero no ha visto eventos; confirma que existe tráfico o logs nuevos.\n"
            "- **Suricata/Zeek:** deben generar los archivos configurados antes de que Sentinel-X pueda analizarlos.\n"
            "- **Base local:** incluye SQLite, WAL y SHM; conserva copias antes de depurar datos."
        )
