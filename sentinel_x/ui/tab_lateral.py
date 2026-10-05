"""Pestaña 5: Detección de movimiento lateral (tráfico este-oeste)."""

import math

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from core import state
from core.config import CONFIG
from modules import lateral_movement
from ui.helpers import boton_exportar_csv


def _grafo_conexiones(eventos: list[dict], marcados: set[str], max_nodos: int = 40) -> go.Figure | None:
    """
    Mapa de comunicaciones internas (ID.AM-03). Disposición circular sin
    dependencias extra: con decenas de hosts es legible y determinista.
    """
    df = pd.DataFrame(eventos)
    if "Inicio" in df.columns:
        df = df[df["Inicio"].fillna(True).astype(bool)]
    df = lateral_movement.solo_trafico_interno(df)
    if df.empty:
        return None
    aristas = df.groupby(["Origen", "Destino"]).size().reset_index(name="n")
    actividad = pd.concat([aristas.groupby("Origen")["n"].sum(), aristas.groupby("Destino")["n"].sum()])
    totales = actividad.groupby(level=0).sum()
    nodos = totales.nlargest(max_nodos).index.tolist()
    aristas = aristas[aristas["Origen"].isin(nodos) & aristas["Destino"].isin(nodos)]

    pos = {ip: (math.cos(2 * math.pi * i / len(nodos)), math.sin(2 * math.pi * i / len(nodos)))
           for i, ip in enumerate(sorted(nodos))}
    max_n = aristas["n"].max() if not aristas.empty else 1
    fig = go.Figure()
    for _, a in aristas.iterrows():
        (x0, y0), (x1, y1) = pos[a["Origen"]], pos[a["Destino"]]
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1], mode="lines", hoverinfo="skip", showlegend=False,
            line=dict(width=1 + 5 * a["n"] / max_n,
                      color="rgba(198,40,40,0.6)" if a["Origen"] in marcados else "rgba(120,120,120,0.35)"),
        ))
    fig.add_trace(go.Scatter(
        x=[pos[ip][0] for ip in nodos], y=[pos[ip][1] for ip in nodos], mode="markers+text",
        text=nodos, textposition="top center", showlegend=False,
        hovertext=[f"{ip}: {int(totales.get(ip, 0))} conexiones" for ip in nodos],
        hoverinfo="text",
        marker=dict(size=14, color=["#c62828" if ip in marcados else "#1e88e5" for ip in nodos]),
    ))
    fig.update_layout(height=520, xaxis=dict(visible=False), yaxis=dict(visible=False),
                      margin=dict(t=30, b=10, l=10, r=10),
                      title="Mapa de conexiones internas (rojo = origen con hallazgos)")
    return fig


def render() -> None:
    st.header("Movimiento lateral (tráfico interno)")
    st.markdown(
        "Analiza conexiones **dentro** de la red local: detecta reconocimiento "
        "interno (fan-out) y uso de puertos administrativos sensibles entre hosts."
    )

    snapshot = state.snapshot(state.eventos_lan, state.lock_eventos_lan)

    c1, c2, c3 = st.columns(3)
    c1.metric("Eventos LAN capturados", len(snapshot))
    c2.metric("IPs origen únicas", len({e["Origen"] for e in snapshot}) if snapshot else 0)
    c3.metric("IPs destino únicas", len({e["Destino"] for e in snapshot}) if snapshot else 0)

    if not snapshot:
        st.caption(
            "Esperando tráfico interno. Asegúrate de que el sniffer LAN esté activo "
            "(ver estado en la barra lateral) y de generar tráfico entre hosts de tu red."
        )
        return

    st.markdown("---")
    col_umbral, col_ventana, col_limpiar = st.columns([1, 1, 1])
    with col_umbral:
        umbral_fanout = st.slider(
            "Umbral fan-out (hosts distintos)", 3, 30, CONFIG["lateral_umbral_fanout"]
        )
    with col_ventana:
        ventana_seg = st.slider(
            "Ventana de tiempo (segundos)", 30, 600, CONFIG["lateral_ventana_seg"], step=30
        )
    with col_limpiar:
        st.write("")
        if st.button("🗑️ Limpiar buffer LAN"):
            with state.lock_eventos_lan:
                state.eventos_lan.clear()
            st.success("Buffer reiniciado.")
            st.rerun()

    if st.button("🔎 Analizar movimiento lateral", type="primary"):
        with st.spinner("Calculando fan-out y puertos de riesgo..."):
            df_fanout = lateral_movement.detectar_fanout(snapshot, umbral_fanout, ventana_seg)
            df_puertos = lateral_movement.detectar_puertos_riesgo(snapshot)
            st.session_state["_df_fanout"] = df_fanout
            st.session_state["_df_puertos_riesgo"] = df_puertos

    df_fanout = st.session_state.get("_df_fanout", pd.DataFrame())
    df_puertos = st.session_state.get("_df_puertos_riesgo", pd.DataFrame())

    st.markdown("#### Reconocimiento interno (fan-out)")
    if not df_fanout.empty:
        st.error(f"⚠️ {len(df_fanout)} host(s) con patrón de escaneo interno")
        st.dataframe(df_fanout, width="stretch")
        boton_exportar_csv(df_fanout, "fanout_lateral.csv", key="csv_fanout")
    elif "_df_fanout" in st.session_state:
        st.success("Sin patrones de fan-out detectados.")
    else:
        st.caption("Pulsa 'Analizar movimiento lateral' para calcular.")

    st.markdown("#### Puertos administrativos sensibles")
    if not df_puertos.empty:
        st.warning(f"⚠️ {len(df_puertos)} combinación(es) origen-destino-puerto detectadas")
        st.dataframe(df_puertos, width="stretch")
        boton_exportar_csv(df_puertos, "puertos_riesgo.csv", key="csv_puertos")
    elif "_df_puertos_riesgo" in st.session_state:
        st.success("Sin conexiones a puertos sensibles detectadas.")

    st.markdown("#### Mapa de comunicaciones internas")
    marcados = set()
    for df_h in (df_fanout, df_puertos):
        if not df_h.empty and "IP origen" in df_h.columns:
            marcados |= set(df_h["IP origen"])
    fig = _grafo_conexiones(snapshot, marcados)
    if fig is None:
        st.caption("Sin conexiones entre hosts internos todavía.")
    else:
        st.plotly_chart(fig, width="stretch")
