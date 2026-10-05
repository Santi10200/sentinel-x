"""Pestaña 6: Baseline de comportamiento (ML), logs Zeek y estado de Threat Intel."""

import pandas as pd
import streamlit as st

from core import state
from core.config import CONFIG
from modules import ml_baseline, threat_intel
from ui.helpers import boton_exportar_csv


def _seccion_ml() -> None:
    st.subheader("Baseline de comportamiento (Machine Learning)")
    st.markdown(
        "Entrena un modelo `IsolationForest` por host a partir del tráfico capturado "
        "y detecta desviaciones respecto a su propio comportamiento histórico."
    )

    flujos_tls = state.snapshot(state.flujos_tls, state.lock_flujos_tls)
    eventos_lan = state.snapshot(state.eventos_lan, state.lock_eventos_lan)
    datos_entrenamiento = eventos_lan or flujos_tls

    c1, c2 = st.columns(2)
    with c1:
        if st.button("🧠 Entrenar baseline con datos actuales"):
            with st.spinner("Entrenando IsolationForest por host..."):
                entrenados = ml_baseline.entrenar_baseline(datos_entrenamiento)
            if entrenados:
                st.success(f"Modelos entrenados para {len(entrenados)} host(s).")
                st.session_state["_ml_entrenados"] = entrenados
            else:
                st.warning(
                    f"Sin suficientes muestras todavía. Se necesitan al menos "
                    f"{CONFIG['ml_min_muestras_entrenamiento']} ventanas de 1 minuto por host."
                )
    with c2:
        hosts_modelo = ml_baseline.hosts_con_modelo_entrenado()
        st.metric("Hosts con modelo entrenado", len(hosts_modelo))

    if st.button("🔍 Detectar anomalías"):
        with st.spinner("Puntuando comportamiento reciente..."):
            df_anomalias = ml_baseline.detectar_anomalias(datos_entrenamiento)
            st.session_state["_df_anomalias_ml"] = df_anomalias

    df_anomalias = st.session_state.get("_df_anomalias_ml", pd.DataFrame())
    if not df_anomalias.empty:
        st.error(f"⚠️ {len(df_anomalias)} ventana(s) anómalas detectadas")
        st.dataframe(df_anomalias, width="stretch")
        boton_exportar_csv(df_anomalias, "anomalias_ml.csv", key="csv_ml")
    elif "_df_anomalias_ml" in st.session_state:
        st.success("Sin anomalías detectadas respecto al baseline entrenado.")


def _seccion_zeek() -> None:
    st.subheader("Logs Zeek")
    st.markdown(
        f"Siguiendo en vivo: `{CONFIG['dir_zeek_logs']}` (conn, dns, ssl, http, files, notice)."
    )

    eventos = state.snapshot(state.eventos_zeek, state.lock_zeek)
    if not eventos:
        st.caption(
            "Sin eventos Zeek todavía. Verifica que Zeek esté corriendo con "
            "`redef LogAscii::use_json = T;` en su configuración."
        )
        return

    df = pd.DataFrame(eventos)
    tipos_disponibles = sorted(df["tipo_log"].unique().tolist())
    tipo_sel = st.selectbox("Tipo de log:", tipos_disponibles)

    df_tipo = df[df["tipo_log"] == tipo_sel].drop(columns=["tipo_log"]).dropna(axis=1, how="all")
    st.dataframe(df_tipo.tail(100), width="stretch")
    boton_exportar_csv(df_tipo, f"zeek_{tipo_sel}.csv", key=f"csv_zeek_{tipo_sel}")


def _seccion_ti() -> None:
    st.subheader("Threat Intelligence")
    stats = threat_intel.estadisticas_feeds()

    c1, c2, c3 = st.columns(3)
    c1.metric("IPs C2 conocidas (Feodo)", stats["ips_maliciosas"])
    c2.metric("Dominios maliciosos (URLhaus)", stats["dominios_maliciosos"])
    c3.metric("CVEs con explotación activa (KEV)", stats["cves_kev"])

    if stats["ultima_actualizacion"]:
        import datetime
        ts = datetime.datetime.fromtimestamp(stats["ultima_actualizacion"])
        st.caption(f"Última actualización de feeds: {ts.strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        st.caption("Feeds aún no actualizados.")

    if st.button("🔄 Forzar actualización de feeds"):
        with st.spinner("Descargando Feodo Tracker, URLhaus y CISA KEV..."):
            threat_intel.actualizar_feeds()
        st.success("Feeds actualizados.")
        st.rerun()


def render() -> None:
    st.header("Baseline ML · Zeek · Threat Intelligence")

    sub1, sub2, sub3 = st.tabs(["🧠 Baseline ML", "📜 Logs Zeek", "🌐 Threat Intel"])
    with sub1:
        _seccion_ml()
    with sub2:
        _seccion_zeek()
    with sub3:
        _seccion_ti()
