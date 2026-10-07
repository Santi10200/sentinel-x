"""Pestaña de inicio: panel general con KPIs y gráficos de toda la red."""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from core import state
from modules import analisis, nist_csf
from ui.helpers import COLORES_SEVERIDAD, badge_severidad, boton_analisis


def _actividad_por_minuto(resultado: dict) -> pd.DataFrame:
    filas = []
    for fuente, eventos in (("TLS", resultado["flujos_tls"]), ("LAN", resultado["eventos_lan"]),
                            ("Alertas IDS", resultado["alertas"])):
        for e in eventos[-5000:]:
            filas.append({"Fuente": fuente, "Timestamp": e.get("Timestamp")})
    if not filas:
        return pd.DataFrame()
    df = pd.DataFrame(filas).dropna()
    df["Minuto"] = pd.to_datetime(df["Timestamp"], unit="s").dt.floor("min")
    return df.groupby(["Minuto", "Fuente"]).size().reset_index(name="Eventos")


def _top_hablantes(resultado: dict, n: int = 10) -> pd.DataFrame:
    eventos = resultado["eventos_lan"] + resultado["flujos_tls"]
    if not eventos:
        return pd.DataFrame()
    df = pd.DataFrame(eventos)
    if "Tamaño (bytes)" not in df.columns:
        return pd.DataFrame()
    return (df.groupby("Origen")["Tamaño (bytes)"].sum().nlargest(n)
            .reset_index().rename(columns={"Tamaño (bytes)": "Bytes"}))


def _top_servicios(resultado: dict, n: int = 10) -> pd.DataFrame:
    if not resultado["eventos_lan"]:
        return pd.DataFrame()
    df = pd.DataFrame(resultado["eventos_lan"])
    if "Inicio" in df.columns:
        df = df[df["Inicio"].fillna(True).astype(bool)]
    if df.empty:
        return pd.DataFrame()
    df["Servicio"] = df["Proto"].astype(str) + "/" + df["Puerto"].astype(str)
    return df["Servicio"].value_counts().head(n).reset_index().rename(columns={"count": "Conexiones"})


def render() -> None:
    st.header("Panel general de seguridad de la red")
    st.markdown(
        "Vista de conjunto para estudiantes y responsables de TI: **qué hay** en la red, "
        "**qué está pasando** y **qué tan cerca** está de los resultados de NIST CSF 2.0."
    )

    resultado = boton_analisis("analisis_resumen")

    if not resultado:
        c1, c2, c3 = st.columns(3)
        c1.metric("Paquetes TLS en memoria", len(state.flujos_tls))
        c2.metric("Eventos LAN en memoria", len(state.eventos_lan))
        c3.metric("Alertas IDS en memoria", len(state.alertas_ids))
        st.info(
            "Pulsa **Ejecutar análisis completo** para correlacionar todo lo capturado, "
            "evaluar la postura de seguridad y calcular el perfil NIST CSF."
        )
        st.markdown(
            "**Primeros pasos recomendados:**\n"
            "1. Pestaña *Dispositivos*: escanea tu red (con Nmap para inventariar servicios).\n"
            "2. Deja capturar tráfico unos minutos (sniffers en la barra lateral en verde).\n"
            "3. Vuelve aquí y ejecuta el análisis.\n"
            "4. Revisa *NIST CSF* para el plan de acción y descarga el informe."
        )
        return

    incidentes = resultado["incidentes"]
    df_postura = resultado["df_postura"]
    global_ = resultado["nist_global"]

    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("Puntuación NIST CSF", f"{global_:.0f}/100" if global_ is not None else "—",
              help=nist_csf.nivel_orientativo(global_))
    k2.metric("Dispositivos", len(resultado["inventario"]))
    k3.metric("Incidentes", len(incidentes))
    k4.metric("Críticos / altos", sum(1 for i in incidentes if i["severidad"] in ("Crítica", "Alta")))
    k5.metric("Hallazgos de postura", len(df_postura))
    k6.metric("Casos abiertos", sum(1 for c in resultado["casos"] if c["estado"] != "Cerrado"))

    g1, g2 = st.columns(2)
    with g1:
        df_sev = analisis.conteo_por_severidad(incidentes, df_postura)
        fig = px.bar(df_sev, x="Severidad", y="Cantidad", color="Severidad", facet_col="Origen",
                     color_discrete_map=COLORES_SEVERIDAD, height=320,
                     category_orders={"Severidad": list(COLORES_SEVERIDAD)},
                     title="Severidad: incidentes (ataques) vs postura (exposición)")
        fig.update_layout(showlegend=False, margin=dict(t=60, b=10))
        st.plotly_chart(fig, width="stretch")
    with g2:
        df_puntos = resultado["df_nist_puntos"]
        valores = df_puntos["Puntuación"].fillna(0).tolist()
        etiquetas = [f.split(" (")[0] for f in df_puntos["Función"]]
        fig = go.Figure(go.Scatterpolar(r=valores + valores[:1], theta=etiquetas + etiquetas[:1],
                                        fill="toself", name="Perfil actual"))
        fig.update_layout(polar=dict(radialaxis=dict(range=[0, 100])), height=320,
                          title="Perfil NIST CSF 2.0 por función (0-100)", margin=dict(t=60, b=10))
        st.plotly_chart(fig, width="stretch")

    df_act = _actividad_por_minuto(resultado)
    if not df_act.empty:
        fig = px.area(df_act, x="Minuto", y="Eventos", color="Fuente", height=280,
                      title="Actividad capturada por minuto")
        fig.update_layout(margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")

    g3, g4 = st.columns(2)
    with g3:
        df_top = _top_hablantes(resultado)
        if not df_top.empty:
            fig = px.bar(df_top, x="Bytes", y="Origen", orientation="h", height=320,
                         title="Hosts con más tráfico (bytes capturados)")
            fig.update_layout(yaxis=dict(autorange="reversed"), margin=dict(t=50, b=10))
            st.plotly_chart(fig, width="stretch")
    with g4:
        df_srv = _top_servicios(resultado)
        if not df_srv.empty:
            fig = px.bar(df_srv, x="Conexiones", y="Servicio", orientation="h", height=320,
                         title="Servicios más usados en la LAN (conexiones nuevas)")
            fig.update_layout(yaxis=dict(autorange="reversed"), margin=dict(t=50, b=10))
            st.plotly_chart(fig, width="stretch")

    st.markdown("#### Lo más urgente")
    u1, u2 = st.columns(2)
    with u1:
        st.markdown("**Incidentes principales**")
        if not incidentes:
            st.success("Sin incidentes correlacionados.")
        for inc in incidentes[:5]:
            st.markdown(f"- {badge_severidad(inc['severidad'])} `{inc['ip_principal']}` · "
                        f"{', '.join(inc['fuentes'])}")
    with u2:
        st.markdown("**Exposición más grave**")
        if df_postura.empty:
            st.success("Sin hallazgos de postura con los datos disponibles.")
        for _, h in df_postura.head(5).iterrows():
            st.markdown(f"- {badge_severidad(h['Severidad'])} `{h['Activo']}` · {h['Detalle']}")
