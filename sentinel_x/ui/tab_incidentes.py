"""Pestaña 1: Vista unificada de incidentes correlacionados."""

import streamlit as st

from core import state
from core.config import CONFIG
from modules import beaconing, lateral_movement, ml_baseline, correlation_engine
from ui.helpers import boton_exportar_csv


def render() -> None:
    st.header("Resumen de incidentes")
    st.markdown(
        "Vista correlacionada: une beaconing, movimiento lateral, anomalías ML "
        "y alertas IDS por IP. La severidad sube cuando varias fuentes coinciden."
    )

    if st.button("🔎 Recalcular correlación", type="primary"):
        with st.spinner("Cruzando hallazgos de todos los módulos..."):
            flujos_tls = state.snapshot(state.flujos_tls, state.lock_flujos_tls)
            eventos_lan = state.snapshot(state.eventos_lan, state.lock_eventos_lan)
            alertas = state.snapshot(state.alertas_ids, state.lock_alertas)

            df_beacons = beaconing.detectar(flujos_tls)
            df_fanout = lateral_movement.detectar_fanout(eventos_lan)
            df_puertos = lateral_movement.detectar_puertos_riesgo(eventos_lan)
            df_ml = ml_baseline.detectar_anomalias(eventos_lan or flujos_tls)

            incidentes = correlation_engine.correlacionar(
                df_beacons, df_fanout, df_puertos, df_ml, list(alertas)[-200:]
            )
            st.session_state["_incidentes_calculados"] = incidentes

    incidentes = st.session_state.get("_incidentes_calculados", [])

    if not incidentes:
        st.info(
            "Sin incidentes calculados aún. Pulsa 'Recalcular correlación' para analizar "
            "los datos capturados hasta ahora."
        )
        return

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Incidentes totales", len(incidentes))
    m2.metric("Críticos", sum(1 for i in incidentes if i["severidad"] == "Crítica"))
    m3.metric("Altos", sum(1 for i in incidentes if i["severidad"] == "Alta"))
    m4.metric(
        "Corroborados por 2+ fuentes",
        sum(1 for i in incidentes if i["num_fuentes"] >= 2),
    )

    df_resumen = correlation_engine.resumen_a_dataframe(incidentes)
    st.dataframe(df_resumen, use_container_width=True)
    boton_exportar_csv(df_resumen, "incidentes_correlacionados.csv")

    st.markdown("#### Detalle por incidente")
    ips_disponibles = [i["ip_principal"] for i in incidentes]
    ip_sel = st.selectbox("Selecciona una IP para ver el detalle completo:", ips_disponibles)

    incidente_sel = next((i for i in incidentes if i["ip_principal"] == ip_sel), None)
    if incidente_sel:
        with st.expander(f"Incidente: {ip_sel}", expanded=True):
            st.markdown(f"**Severidad:** {incidente_sel['severidad']}")
            st.markdown(f"**Fuentes que corroboran:** {', '.join(incidente_sel['fuentes'])}")
            if incidente_sel["mitre_tecnicas"]:
                st.markdown(f"**Técnicas MITRE ATT&CK:** {', '.join(incidente_sel['mitre_tecnicas'])}")
            st.markdown("**Hallazgos individuales:**")
            for h in incidente_sel["hallazgos"]:
                st.markdown(f"- `[{h['fuente']}]` {h['descripcion']}")
