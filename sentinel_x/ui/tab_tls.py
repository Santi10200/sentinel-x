"""Pestaña 4: Tráfico cifrado, JA3 y detección de beaconing/DGA."""

import pandas as pd
import streamlit as st

from core import state
from core.config import CONFIG
from modules import beaconing, tls_analysis
from ui.helpers import boton_exportar_csv


def render() -> None:
    st.header("Tráfico cifrado: JA3 y beaconing")
    st.markdown(
        "Captura TCP en puertos 443/8443 con reensamblado de sesión. JA3 completo "
        "(SSLVersion · Ciphers · Extensions · EllipticCurves · ECPointFormats)."
    )

    snapshot = state.snapshot(state.flujos_tls, state.lock_flujos_tls)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Paquetes TLS capturados", len(snapshot))
    c2.metric("Destinos únicos (SNI)", len({f["SNI"] for f in snapshot}) if snapshot else 0)
    c3.metric("Huellas JA3 únicas", len({f["JA3"] for f in snapshot}) if snapshot else 0)
    ja3_conocidos = sum(1 for f in snapshot if tls_analysis.identificar_ja3(f.get("JA3", "")))
    c4.metric("JA3 identificados", ja3_conocidos)

    st.markdown("---")
    col_min, col_cv, col_limpiar = st.columns([1, 1, 1])
    with col_min:
        min_paquetes = st.slider("Mínimo de paquetes", 3, 20, CONFIG["beacon_min_paquetes"])
    with col_cv:
        umbral_cv = st.slider("Umbral CV", 0.01, 0.5, CONFIG["beacon_umbral_cv"], 0.01)
    with col_limpiar:
        st.write("")
        if st.button("🗑️ Limpiar buffer TLS"):
            with state.lock_flujos_tls:
                state.flujos_tls.clear()
            st.success("Buffer reiniciado.")
            st.rerun()

    if st.button("🔎 Analizar beaconing y DGA", type="primary"):
        with st.spinner("Calculando CV, entropía DGA y cruzando con Threat Intel..."):
            df_beacons = beaconing.detectar(snapshot, min_paquetes, umbral_cv)
            st.session_state["_df_beacons"] = df_beacons

    df_beacons = st.session_state.get("_df_beacons", pd.DataFrame())
    if not df_beacons.empty:
        st.error(f"⚠️ {len(df_beacons)} flujo(s) con señales de C2 / DGA detectados")
        st.dataframe(df_beacons, use_container_width=True)
        boton_exportar_csv(df_beacons, "beacons_detectados.csv")
    elif "_df_beacons" in st.session_state:
        st.success("Sin patrones de beaconing ni DGA detectados con los umbrales actuales.")

    st.markdown("---")
    st.subheader("Timeline de flujos recientes")

    if snapshot:
        df = pd.DataFrame(snapshot)
        df["Hora"] = pd.to_datetime(df["Timestamp"], unit="s")
        df["JA3 conocido"] = df["JA3"].apply(lambda j: tls_analysis.identificar_ja3(j) or "")

        try:
            import plotly.express as px
            fig = px.scatter(
                df.tail(500), x="Hora", y="SNI", color="JA3", size="Tamaño (bytes)",
                hover_data=["Origen", "Destino", "Puerto", "JA3 conocido"],
                title="Flujos TLS: SNI vs tiempo (últimos 500)", height=420,
            )
            fig.update_layout(showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        except ImportError:
            st.info("Instala `plotly` para ver el gráfico: `pip install plotly`")

        cols = ["Hora", "Origen", "Destino", "Puerto", "SNI", "JA3", "JA3 conocido", "Tamaño (bytes)"]
        df_tabla = df[cols].tail(50).copy()
        df_tabla["Hora"] = df_tabla["Hora"].dt.strftime("%H:%M:%S")
        st.dataframe(df_tabla, use_container_width=True)
        boton_exportar_csv(df_tabla, "flujos_tls.csv")
    else:
        st.caption("Esperando paquetes TLS. Genera tráfico HTTPS para activar el sniffer.")
