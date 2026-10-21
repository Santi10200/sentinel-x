"""Centro SOC: prioridades, cobertura y tendencia en una única vista."""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from modules import analisis, correlation_engine, dashboard_metrics, nist_csf, sensor_health
from ui.helpers import COLORES_SEVERIDAD, aplicar_estilo_soc, boton_analisis


def _actividad_por_minuto(resultado: dict) -> pd.DataFrame:
    filas = []
    for fuente, eventos in (("TLS", resultado["flujos_tls"]), ("LAN", resultado["eventos_lan"]),
                            ("Alertas IDS", resultado["alertas"])):
        filas.extend({"Fuente": fuente, "Timestamp": e["Timestamp"]} for e in eventos[-5000:] if e.get("Timestamp"))
    if not filas:
        return pd.DataFrame()
    df = pd.DataFrame(filas)
    df["Minuto"] = pd.to_datetime(df["Timestamp"], unit="s").dt.floor("min")
    return df.groupby(["Minuto", "Fuente"]).size().reset_index(name="Eventos")


def _salud() -> tuple[int, int, str, list[dict]]:
    resumen = sensor_health.resumen()
    fuentes = [f for f in resumen["fuentes"] if f["Estado"] != "No configurado"]
    return sum(f["Estado"] == "Operativo" for f in fuentes), len(fuentes), resumen["estado_global"], fuentes


def _prioridad(resultado: dict) -> tuple[str, str]:
    if resultado["incidentes"]:
        incidente = resultado["incidentes"][0]
        return f"Investigar {incidente['ip_principal']}", f"{incidente['severidad']} · {', '.join(incidente['fuentes'])}"
    if not resultado["df_postura"].empty:
        fila = resultado["df_postura"].iloc[0]
        return f"Revisar {fila['Activo']}", f"{fila['Severidad']} · {fila['Detalle']}"
    return "Mantener supervisión", "Sin incidentes correlacionados ni exposición prioritaria."


def _grafico_nist(resultado: dict) -> go.Figure:
    puntos = resultado["df_nist_puntos"]
    valores = puntos["Puntuación"].fillna(0).tolist()
    etiquetas = [f.split(" (")[0] for f in puntos["Función"]]
    fig = go.Figure(go.Scatterpolar(r=valores + valores[:1], theta=etiquetas + etiquetas[:1],
                                    fill="toself", line_color="#32c48d"))
    fig.update_layout(showlegend=False, height=310, margin=dict(t=15, b=10),
                      paper_bgcolor="rgba(0,0,0,0)", font_color="#d7e4ef",
                      polar=dict(bgcolor="rgba(10,31,48,.55)", radialaxis=dict(range=[0, 100], gridcolor="#29475f"),
                                 angularaxis=dict(gridcolor="#29475f")))
    return fig


def render() -> None:
    aplicar_estilo_soc()
    st.header("Centro SOC")
    st.caption("Riesgo, cobertura y prioridades operativas en una sola vista.")
    resultado = boton_analisis("analisis_resumen")
    operativas, total, estado_sensor, fuentes = _salud()

    if not resultado:
        st.markdown("<div class='soc-hero'><div class='soc-kicker'>Centro de operaciones</div>"
                    "<h2>Prepara una fotografía de seguridad</h2><p>Unifica detecciones, postura y cobertura para priorizar el siguiente paso.</p></div>",
                    unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        c1.metric("Sensores operativos", f"{operativas}/{total}")
        c2.metric("Estado del sensor", estado_sensor)
        c3.metric("Alertas en memoria", len(st.session_state.get("_alertas_vistas", [])))
        st.info("Ejecuta el análisis completo para calcular riesgo, priorizar incidentes y ver tendencias.")
        return

    incidentes, postura = resultado["incidentes"], resultado["df_postura"]
    riesgo = dashboard_metrics.riesgo_global(incidentes, postura)
    accion, detalle_accion = _prioridad(resultado)
    hero, accion_col = st.columns([3, 1])
    with hero:
        st.markdown(f"<div class='soc-hero'><div class='soc-kicker'>Panorama de seguridad</div>"
                    f"<div class='soc-risk'>{riesgo['puntuacion']}/100 · {riesgo['nivel']}</div>"
                    f"<p>{riesgo['explicacion']}. Indicador de priorización, no certificación.</p></div>", unsafe_allow_html=True)
    with accion_col:
        st.metric("Sensores", f"{operativas}/{total}", estado_sensor)
        if st.button("Ver prioridad", type="primary", key="soc_prioridad"):
            st.session_state["_soc_prioridad_visible"] = True
    if st.session_state.get("_soc_prioridad_visible"):
        st.info(f"**Atender ahora: {accion}** · {detalle_accion}")

    global_ = resultado["nist_global"]
    casos = sum(c["estado"] != "Cerrado" for c in resultado["casos"])
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Incidentes abiertos", len(incidentes))
    k2.metric("Críticos / altos", sum(i["severidad"] in ("Crítica", "Alta") for i in incidentes))
    k3.metric("Postura NIST", f"{global_:.0f}/100" if global_ is not None else "—", help=nist_csf.nivel_orientativo(global_))
    k4.metric("Casos en curso", casos)

    izquierda, derecha = st.columns([3, 2])
    with izquierda:
        st.subheader("Prioridades operativas")
        df_incidentes = correlation_engine.resumen_a_dataframe(incidentes)
        if df_incidentes.empty:
            st.success("Sin incidentes correlacionados. Revisa exposición y cobertura antes de concluir que no hay riesgo.")
        else:
            st.dataframe(df_incidentes.head(8), width="stretch", hide_index=True)
    with derecha:
        st.subheader("Cobertura del sensor")
        st.dataframe(pd.DataFrame(fuentes)[["Fuente", "Estado", "Detalle", "Eventos"]], width="stretch", hide_index=True)

    tendencia, nist = st.columns([3, 2])
    with tendencia:
        st.subheader("Actividad de alertas")
        actividad = _actividad_por_minuto(resultado)
        if actividad.empty:
            st.caption("Aún no hay telemetría con marca de tiempo para construir una tendencia.")
        else:
            fig = px.area(actividad, x="Minuto", y="Eventos", color="Fuente", height=310,
                          color_discrete_map={"TLS": "#32c48d", "LAN": "#409cff", "Alertas IDS": "#ff8c42"})
            fig.update_layout(margin=dict(t=15, b=10), legend_title_text="", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,31,48,.55)", font_color="#d7e4ef")
            st.plotly_chart(fig, width="stretch")
    with nist:
        st.subheader("Postura NIST")
        st.plotly_chart(_grafico_nist(resultado), width="stretch")

    st.subheader("Contexto de riesgo")
    severidad = analisis.conteo_por_severidad(incidentes, postura)
    fig = px.bar(severidad, x="Severidad", y="Cantidad", color="Origen", barmode="group", height=260,
                 category_orders={"Severidad": list(COLORES_SEVERIDAD)}, color_discrete_map={"Incidentes": "#ff6b6b", "Postura": "#ffbf69"})
    fig.update_layout(margin=dict(t=15, b=10), legend_title_text="", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(10,31,48,.55)", font_color="#d7e4ef")
    st.plotly_chart(fig, width="stretch")
