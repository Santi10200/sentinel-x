"""Pestaña NIST CSF 2.0: perfil actual, brechas, autoevaluación, postura e informe."""

import datetime

import plotly.express as px
import streamlit as st

from core.network_iface import cidr_de_interfaz, interfaz_configurada
from modules import analisis, informe, nist_csf
from ui.helpers import COLORES_ESTADO_NIST, boton_analisis, boton_exportar_csv, refrescar_nist

_ICONO_ESTADO = {"Cumple": "🟢", "Parcial": "🟡", "No cumple": "🔴", "Sin datos": "⚪"}


def _perfil(resultado: dict) -> None:
    df_puntos = resultado["df_nist_puntos"]
    global_ = resultado["nist_global"]

    c1, c2 = st.columns([1, 2])
    with c1:
        st.metric("Puntuación global", f"{global_:.0f}/100" if global_ is not None else "—")
        st.markdown(f"**{nist_csf.nivel_orientativo(global_)}**")
        st.caption(
            "Promedio de las subcategorías evaluadas (Cumple = 1, Parcial = 0,5). "
            "Los niveles se inspiran en los Tiers del CSF, que no tienen umbrales numéricos "
            "oficiales: es una guía para priorizar, no una certificación."
        )
    with c2:
        df_graf = df_puntos.copy()
        df_graf["Puntuación"] = df_graf["Puntuación"].fillna(0)
        fig = px.bar(df_graf, x="Puntuación", y="Función", orientation="h", range_x=[0, 100],
                     text=df_puntos["Nivel orientativo"], height=300, color="Puntuación",
                     color_continuous_scale=["#c62828", "#f9a825", "#2e7d32"], range_color=[0, 100])
        fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False, margin=dict(t=10, b=10))
        st.plotly_chart(fig, width="stretch")

    df_nist = resultado["df_nist"]
    conteo = df_nist.groupby(["Función", "Estado"]).size().reset_index(name="Subcategorías")
    fig = px.bar(conteo, x="Subcategorías", y="Función", color="Estado", orientation="h", height=280,
                 color_discrete_map=COLORES_ESTADO_NIST, title="Estado de las subcategorías por función",
                 category_orders={"Función": list(nist_csf.FUNCIONES.values()),
                                  "Estado": list(COLORES_ESTADO_NIST)})
    fig.update_layout(yaxis=dict(autorange="reversed"), margin=dict(t=50, b=10))
    st.plotly_chart(fig, width="stretch")


def _subcategorias(resultado: dict) -> None:
    df = resultado["df_nist"].copy()
    f1, f2 = st.columns(2)
    with f1:
        funciones = st.multiselect("Función", list(nist_csf.FUNCIONES.values()),
                                   default=list(nist_csf.FUNCIONES.values()))
    with f2:
        estados = st.multiselect("Estado", list(_ICONO_ESTADO), default=list(_ICONO_ESTADO))
    df = df[df["Función"].isin(funciones) & df["Estado"].isin(estados)]
    df["Estado"] = df["Estado"].map(lambda e: f"{_ICONO_ESTADO.get(e, '')} {e}")
    st.dataframe(df, width="stretch", hide_index=True)
    boton_exportar_csv(df, "perfil_nist_csf.csv", key="csv_nist")


def _autoevaluacion(resultado: dict) -> None:
    st.markdown(
        "Estas subcategorías no se pueden observar en el tráfico de red. "
        "Respóndelas con honestidad: se guardan en la base de datos y cuentan en la puntuación."
    )
    guardadas = analisis.autoevaluacion_guardada()
    opciones = [nist_csf.SIN_DATOS] + nist_csf.ESTADOS_MANUALES
    with st.form("form_autoevaluacion"):
        respuestas = {}
        for sub, guia in nist_csf.MANUALES.items():
            actual = guardadas.get(sub, nist_csf.SIN_DATOS)
            respuestas[sub] = st.radio(
                f"**{sub}** · {nist_csf.SUBCATEGORIAS[sub]}", opciones,
                index=opciones.index(actual) if actual in opciones else 0,
                horizontal=True, help=guia, key=f"auto_{sub}",
            )
        if st.form_submit_button("💾 Guardar autoevaluación"):
            for sub, estado in respuestas.items():
                analisis.guardar_autoevaluacion(sub, estado)
            refrescar_nist()
            st.success("Autoevaluación guardada.")
            st.rerun()


def _postura(resultado: dict) -> None:
    df = resultado["df_postura"]
    st.markdown(
        "Exposición detectada con los datos actuales: servicios inseguros (requiere escaneo Nmap), "
        "protocolos en texto claro observados en la LAN y redes Wi-Fi débiles."
    )
    if df.empty:
        st.success("Sin hallazgos de postura con los datos disponibles.")
        return
    c1, c2 = st.columns([1, 2])
    with c1:
        fig = px.pie(df, names="Categoría", hole=0.5, height=300, title="Hallazgos por categoría")
        fig.update_layout(margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")
    with c2:
        st.dataframe(df, width="stretch", hide_index=True, height=300)
    boton_exportar_csv(df, "postura_seguridad.csv", key="csv_postura")


def _informe(resultado: dict) -> None:
    st.markdown(
        "Informe HTML autocontenido (sin dependencias externas): resumen ejecutivo, perfil CSF, "
        "plan de acción, incidentes, casos y hallazgos. Ábrelo en el navegador e imprímelo a PDF."
    )
    organizacion = st.text_input("Organización / práctica (opcional)", key="informe_org")
    for i, accion in enumerate(informe.plan_de_accion(resultado["df_nist"], resultado["df_postura"]), 1):
        st.markdown(f"{i}. {accion}")
    contenido = informe.generar_html(resultado, red=cidr_de_interfaz(interfaz_configurada()),
                                     organizacion=organizacion.strip())
    nombre = f"informe_sentinel_x_{datetime.datetime.now():%Y%m%d_%H%M}.html"
    st.download_button("📄 Descargar informe (HTML)", data=contenido.encode("utf-8"),
                       file_name=nombre, mime="text/html", type="primary")


def render() -> None:
    st.header("Evaluación NIST Cybersecurity Framework 2.0")
    st.markdown(
        "Perfil actual de la red frente a las 6 funciones del CSF 2.0: **Gobernar, Identificar, "
        "Proteger, Detectar, Responder y Recuperar**. Cada subcategoría muestra la evidencia usada "
        "y qué hacer para mejorarla."
    )
    resultado = boton_analisis("analisis_nist")
    if not resultado:
        st.info("Ejecuta el análisis para calcular el perfil NIST CSF.")
        return

    sub1, sub2, sub3, sub4, sub5 = st.tabs([
        "📊 Perfil", "📋 Subcategorías", "✍️ Autoevaluación", "🛡️ Postura", "📄 Informe",
    ])
    with sub1:
        _perfil(resultado)
    with sub2:
        _subcategorias(resultado)
    with sub3:
        _autoevaluacion(resultado)
    with sub4:
        _postura(resultado)
    with sub5:
        _informe(resultado)
