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


COLORES_SEVERIDAD = {"Crítica": "#c62828", "Alta": "#ef6c00", "Media": "#f9a825", "Baja": "#1e88e5"}
COLORES_ESTADO_NIST = {"Cumple": "#2e7d32", "Parcial": "#f9a825", "No cumple": "#c62828", "Sin datos": "#9e9e9e"}


def analisis_actual() -> dict | None:
    """Último resultado de modules.analisis guardado en la sesión, o None."""
    return st.session_state.get("_analisis")


def ejecutar_y_guardar_analisis() -> dict:
    from modules import analisis  # import diferido: evita ciclos al cargar la UI
    with st.spinner("Analizando tráfico, correlacionando y evaluando NIST CSF..."):
        resultado = analisis.ejecutar_analisis()
    st.session_state["_analisis"] = resultado
    return resultado


def refrescar_nist() -> None:
    """Recalcula solo la evaluación NIST (tras abrir casos o autoevaluar)."""
    from modules import analisis
    resultado = analisis_actual()
    if resultado:
        resultado.update(analisis.evaluar_nist(resultado))


def boton_analisis(key: str) -> dict | None:
    """Botón estándar 'Ejecutar análisis' + marca de tiempo del último."""
    import datetime
    col_btn, col_info = st.columns([1, 3])
    with col_btn:
        if st.button("🔎 Ejecutar análisis completo", type="primary", key=key):
            ejecutar_y_guardar_analisis()
    resultado = analisis_actual()
    with col_info:
        if resultado:
            ts = datetime.datetime.fromtimestamp(resultado["timestamp"]).strftime("%H:%M:%S")
            st.caption(f"Último análisis: {ts}. Los datos en vivo siguen llegando; vuelve a ejecutar para actualizar.")
        else:
            st.caption("Aún no se ha ejecutado el análisis en esta sesión.")
    return resultado
