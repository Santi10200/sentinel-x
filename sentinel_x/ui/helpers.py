"""Helpers reutilizables de la interfaz Streamlit."""

import pandas as pd
import streamlit as st

from core import state


def badge_severidad(sev: str) -> str:
    mapa = {"Crítica": "🔴", "Alta": "🟠", "Media": "🟡", "Baja": "🔵"}
    return f"{mapa.get(sev, '⚪')} {sev}"


def boton_exportar_csv(df: pd.DataFrame, nombre_archivo: str, key: str | None = None) -> None:
    if df is None or df.empty:
        return
    st.download_button(
        "⬇️ Exportar CSV",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name=nombre_archivo,
        mime="text/csv",
        key=key,
    )


def estado_hilo_widget(nombre_hilo: str, etiqueta: str) -> None:
    info = state.estado_hilos.get(nombre_hilo, {})
    activo = info.get("activo", False)
    error = info.get("error")
    procesados = info.get("procesados")

    if error:
        st.sidebar.error(f"⛔ {etiqueta}: {error}")
    elif activo:
        extra = f" · {procesados} eventos" if procesados is not None else ""
        st.sidebar.success(f"🟢 {etiqueta}{extra}")
    else:
        st.sidebar.warning(f"🔴 {etiqueta}: inactivo")
