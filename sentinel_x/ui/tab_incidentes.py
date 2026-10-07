"""Pestaña de incidentes: vista correlacionada + gestión de casos (NIST SP 800-61)."""

import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from modules import correlation_engine, mitre_attack, respuesta_incidentes as ri
from ui.helpers import (
    COLORES_SEVERIDAD, badge_severidad, boton_analisis, boton_exportar_csv, refrescar_nist,
)


def _fecha(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _ciclo_de_vida() -> None:
    columnas = st.columns(len(ri.ESTADOS))
    for col, (estado, csf, descripcion) in zip(columnas, ri.ESTADOS):
        col.markdown(f"**{estado}**  \n`{csf}`")
        col.caption(descripcion)


def _incidentes(resultado: dict) -> None:
    incidentes = resultado["incidentes"]
    if not incidentes:
        st.success("Sin incidentes correlacionados con los datos actuales.")
        return

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Incidentes totales", len(incidentes))
    m2.metric("Críticos", sum(1 for i in incidentes if i["severidad"] == "Crítica"))
    m3.metric("Altos", sum(1 for i in incidentes if i["severidad"] == "Alta"))
    m4.metric("Corroborados por 2+ fuentes", sum(1 for i in incidentes if i["num_fuentes"] >= 2))

    df_resumen = correlation_engine.resumen_a_dataframe(incidentes)
    g1, g2 = st.columns(2)
    with g1:
        fig = px.histogram(df_resumen, x="Severidad", color="Severidad", height=260,
                           color_discrete_map=COLORES_SEVERIDAD,
                           category_orders={"Severidad": list(COLORES_SEVERIDAD)},
                           title="Incidentes por severidad")
        fig.update_layout(showlegend=False, margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")
    with g2:
        tecnicas = [t for i in incidentes for t in i["mitre_tecnicas"]]
        if tecnicas:
            df_t = pd.Series(tecnicas).value_counts().reset_index()
            df_t.columns = ["Técnica", "Incidentes"]
            df_t["Táctica"] = df_t["Técnica"].map(
                lambda t: (mitre_attack.info_tecnica(t.split(" ")[0]) or {}).get("tactica", "N/A"))
            fig = px.bar(df_t, x="Incidentes", y="Técnica", color="Táctica", orientation="h",
                         height=260, title="Técnicas MITRE ATT&CK observadas")
            fig.update_layout(margin=dict(t=50, b=10))
            st.plotly_chart(fig, width="stretch")

    ips_con_caso = {c["ip"] for c in ri.listar_casos(solo_abiertos=True)}
    df_resumen.insert(2, "Caso abierto", df_resumen["IP"].map(lambda ip: "Sí" if ip in ips_con_caso else "—"))
    st.dataframe(df_resumen, width="stretch", hide_index=True)
    boton_exportar_csv(df_resumen, "incidentes_correlacionados.csv")

    st.markdown("#### Detalle y declaración de caso")
    ip_sel = st.selectbox("Selecciona una IP:", [i["ip_principal"] for i in incidentes])
    incidente = next((i for i in incidentes if i["ip_principal"] == ip_sel), None)
    if not incidente:
        return
    with st.expander(f"Incidente: {ip_sel}", expanded=True):
        st.markdown(f"**Severidad:** {badge_severidad(incidente['severidad'])} · "
                    f"**Prioridad sugerida:** {ri.PRIORIDAD_POR_SEVERIDAD.get(incidente['severidad'])}")
        st.markdown(f"**Fuentes que corroboran:** {', '.join(incidente['fuentes'])}")
        if incidente["mitre_tecnicas"]:
            st.markdown(f"**Técnicas MITRE ATT&CK:** {', '.join(incidente['mitre_tecnicas'])}")
        st.markdown("**Hallazgos individuales:**")
        for h in incidente["hallazgos"]:
            st.markdown(f"- `[{h['fuente']}]` {h['descripcion']}")
        acciones = ri.acciones_sugeridas(incidente["fuentes"])
        if acciones:
            st.markdown("**Acciones sugeridas:**")
            for accion in acciones:
                st.markdown(f"- {accion}")

        caso = ri.caso_abierto_para_ip(ip_sel)
        if caso:
            st.info(f"Ya existe el caso #{caso['id']} ({caso['estado']}) para esta IP. Gestiónalo abajo.")
        elif st.button("📁 Declarar caso (DE.AE-08)", type="primary"):
            caso_id, _ = ri.abrir_caso(incidente, autor=st.session_state.get("_analista", "analista"))
            refrescar_nist()
            st.success(f"Caso #{caso_id} declarado.")
            st.rerun()


def _casos() -> None:
    solo_abiertos = st.toggle("Solo casos abiertos", value=True)
    casos = ri.listar_casos(solo_abiertos=solo_abiertos)
    if not casos:
        st.caption("No hay casos. Decláralos desde la sub-pestaña de incidentes.")
        return

    df = pd.DataFrame([{
        "#": c["id"], "IP": c["ip"], "Estado": c["estado"], "Prioridad": c["prioridad"],
        "Severidad": c["severidad"], "Fuentes": ", ".join(c["fuentes"]),
        "Abierto": _fecha(c["creado"]), "Actualizado": _fecha(c["actualizado"]),
    } for c in casos])
    st.dataframe(df, width="stretch", hide_index=True)
    boton_exportar_csv(df, "casos_respuesta.csv", key="csv_casos")

    caso_id = st.selectbox("Caso a gestionar:", [c["id"] for c in casos],
                           format_func=lambda i: next(f"#{c['id']} · {c['ip']} · {c['estado']}"
                                                      for c in casos if c["id"] == i))
    caso = ri.obtener_caso(caso_id)
    if not caso:
        return

    c1, c2 = st.columns([1, 1])
    with c1:
        st.markdown(f"**{caso['titulo']}**")
        st.caption(f"Prioridad {caso['prioridad']} · MITRE: {', '.join(caso['mitre']) or '—'}")
        st.markdown(f"_{caso['resumen']}_")
        acciones = ri.acciones_sugeridas(caso["fuentes"])
        if acciones:
            st.markdown("**Playbook sugerido:**")
            for accion in acciones:
                st.markdown(f"- {accion}")
    with c2:
        with st.form(f"form_caso_{caso_id}"):
            autor = st.text_input("Analista", value=st.session_state.get("_analista", "analista"))
            idx = ri.NOMBRES_ESTADO.index(caso["estado"]) if caso["estado"] in ri.NOMBRES_ESTADO else 0
            nuevo_estado = st.selectbox("Estado", ri.NOMBRES_ESTADO, index=idx)
            nota = st.text_area("Nota / acción realizada",
                                placeholder="Ej. Host aislado en VLAN 99; bloqueado dominio en DNS.")
            if st.form_submit_button("💾 Registrar"):
                st.session_state["_analista"] = autor or "analista"
                if nuevo_estado != caso["estado"]:
                    ri.cambiar_estado(caso_id, nuevo_estado, nota, autor)
                elif nota.strip():
                    ri.agregar_nota(caso_id, nota, autor)
                else:
                    st.warning("Sin cambios: cambia el estado o escribe una nota.")
                    st.stop()
                refrescar_nist()
                st.rerun()

    st.markdown("**Historial (RS.AN-06, solo anexar):**")
    for evento in reversed(ri.historial(caso_id)):
        st.markdown(f"- `{_fecha(evento['timestamp'])}` **{evento['estado']}** · "
                    f"{evento['autor']}: {evento['nota']}")


def render() -> None:
    st.header("Incidentes y respuesta")
    st.markdown(
        "Une beaconing, movimiento lateral, anomalías ML y alertas IDS por IP (la severidad sube cuando "
        "varias fuentes coinciden) y gestiona cada caso siguiendo el ciclo de vida de **NIST SP 800-61**."
    )
    resultado = boton_analisis("analisis_incidentes")
    _ciclo_de_vida()

    sub1, sub2 = st.tabs(["🧩 Incidentes correlacionados", "📁 Casos (SP 800-61)"])
    with sub1:
        if resultado:
            _incidentes(resultado)
        else:
            st.info("Ejecuta el análisis para correlacionar los datos capturados.")
    with sub2:
        _casos()
