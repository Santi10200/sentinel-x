"""Pestaña 6: Baseline de comportamiento (ML), logs Zeek y estado de Threat Intel."""

import datetime
import time

import pandas as pd
import plotly.express as px
import streamlit as st

from core import state
from core.config import CONFIG
from modules import ml_baseline, threat_intel
from ui.helpers import boton_exportar_csv


def _seccion_ml() -> None:
    st.subheader("Baseline de comportamiento (Machine Learning)")
    st.markdown(
        "Un modelo `IsolationForest` por host aprende su comportamiento habitual por minuto "
        "(bytes, paquetes, destinos, puertos y hora del día). Las features se guardan en la base "
        f"de datos y el modelo se **reentrena solo cada {CONFIG['ml_reentreno_min']} min** con las "
        f"últimas {CONFIG['ml_ventana_entrenamiento_horas']} h, excluyendo lo que ya era anómalo "
        "para que un ataque sostenido no se aprenda como normal."
    )

    estado = state.estado_hilos.get("ml_baseline", {})
    ultimo = estado.get("ultimo_entrenamiento")
    historial = ml_baseline.cargar_features(time.time() - CONFIG["ml_ventana_entrenamiento_horas"] * 3600)

    c1, c2, c3 = st.columns(3)
    c1.metric("Hosts con modelo", len(ml_baseline.hosts_con_modelo_entrenado()))
    c2.metric("Minutos·host en historial", len(historial))
    c3.metric("Último entrenamiento", time.strftime("%H:%M", time.localtime(ultimo)) if ultimo else "—")

    b1, b2 = st.columns(2)
    with b1:
        if st.button("🧠 Reentrenar ahora"):
            with st.spinner("Guardando features y entrenando IsolationForest por host..."):
                ml_baseline.persistir_features(
                    state.snapshot(state.eventos_lan, state.lock_eventos_lan)
                    + state.snapshot(state.flujos_tls, state.lock_flujos_tls)
                )
                entrenados = ml_baseline.entrenar_desde_historial()
            if entrenados:
                st.success(f"Modelos entrenados para {len(entrenados)} host(s) y guardados en disco.")
            else:
                st.warning(
                    f"Sin suficientes muestras todavía: cada host necesita al menos "
                    f"{CONFIG['ml_min_muestras_entrenamiento']} minutos con tráfico."
                )
    with b2:
        if st.button("🔍 Detectar anomalías (última hora)"):
            st.session_state["_df_anomalias_ml"] = ml_baseline.detectar_anomalias_recientes()

    df_modelos = ml_baseline.resumen_modelos()
    if not df_modelos.empty:
        st.markdown("#### Modelos por host")
        st.dataframe(df_modelos, width="stretch", hide_index=True)

    df_anomalias = st.session_state.get("_df_anomalias_ml", pd.DataFrame())
    if not df_anomalias.empty:
        st.error(f"⚠️ {len(df_anomalias)} minuto(s) anómalos detectados")
        st.dataframe(df_anomalias, width="stretch", hide_index=True)
        boton_exportar_csv(df_anomalias, "anomalias_ml.csv", key="csv_ml")
    elif "_df_anomalias_ml" in st.session_state:
        st.success("Sin anomalías respecto al baseline en la última hora.")

    if not historial.empty:
        st.markdown("#### Histórico por host")
        hosts = sorted(historial["host"].unique().tolist())
        host = st.selectbox("Host", hosts, key="ml_host")
        metrica = st.selectbox("Métrica", ml_baseline.FEATURES_BASE, key="ml_metrica",
                               format_func=lambda f: f.replace("_", " ").capitalize())
        df_h = historial[historial["host"] == host].copy()
        df_h["Hora"] = pd.to_datetime(df_h["minuto"] * 60, unit="s", utc=True).dt.tz_convert(
            datetime.datetime.now().astimezone().tzinfo)
        fig = px.line(df_h, x="Hora", y=metrica, height=300, title=f"{host}: {metrica} por minuto")
        if not df_anomalias.empty:
            anom = df_anomalias[df_anomalias["Host"] == host]
            marcas = df_h[df_h["Hora"].dt.strftime("%Y-%m-%d %H:%M").isin(anom["Minuto"])]
            fig.add_scatter(x=marcas["Hora"], y=marcas[metrica], mode="markers", name="Anomalía",
                            marker=dict(color="#c62828", size=10))
        fig.update_layout(margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")


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
