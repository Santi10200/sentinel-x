"""Pestaña 3: Descubrimiento y perfilado de dispositivos."""

import pandas as pd
import streamlit as st

import plotly.express as px

from core import database
from core.config import CONFIG
from core.network_iface import cidr_de_interfaz, interfaz_configurada
from modules import device_profiler, threat_intel, vulnerabilidades
from ui.helpers import boton_exportar_csv


def _seccion_cve() -> None:
    st.markdown("#### Vulnerabilidades conocidas (NVD · CISA KEV)")
    st.caption(
        "Cruza el producto y versión que identificó Nmap (CPE) con la base de datos de "
        "vulnerabilidades del NIST y marca las que CISA tiene registradas como explotadas "
        "activamente. NIST CSF 2.0: ID.RA-01 / ID.RA-02."
    )
    inventario = database.consultar("SELECT * FROM inventario_red")
    servicios = vulnerabilidades.servicios_con_cpe(inventario)

    c1, c2, c3 = st.columns(3)
    c1.metric("Servicios con versión (CPE)", len(servicios))
    c2.metric("Clave API NVD", "Sí" if CONFIG["nvd_api_key"] else "No")
    c3.metric("CVE en CISA KEV cargados", threat_intel.estadisticas_feeds()["cves_kev"])

    if not servicios:
        st.info("Ejecuta un escaneo con **Nmap -O -sV** activado para identificar versiones.")
    else:
        if not CONFIG["nvd_api_key"]:
            st.caption(
                f"Sin clave API el NVD permite ~5 consultas cada 30 s: unos {len(servicios) * 6} s para "
                "este inventario (las respuestas se cachean). Clave gratuita: variable SENTINEL_NVD_API_KEY."
            )
        if not threat_intel.estadisticas_feeds()["cves_kev"]:
            st.warning("Catálogo CISA KEV no cargado: no se podrá marcar la explotación activa.")
        if st.button("🛡️ Buscar CVE en el NVD"):
            barra = st.progress(0.0, text="Consultando el NVD...")
            resumen = vulnerabilidades.buscar_vulnerabilidades(
                inventario, progreso=lambda i, n, txt: barra.progress(i / n, text=f"{i}/{n} · {txt}"),
            )
            barra.empty()
            if resumen["fallidos"] and not resumen["consultados"]:
                st.error("No se pudo contactar con el NVD. Revisa la conexión a services.nvd.nist.gov.")
            else:
                st.success(
                    f"{resumen['consultados']} servicios consultados · {resumen['cves']} CVE · "
                    f"{resumen['kev']} con explotación activa (KEV)"
                    + (f" · {resumen['fallidos']} sin respuesta" if resumen["fallidos"] else "")
                )

    filas = vulnerabilidades.vulnerabilidades_guardadas()
    if not filas:
        return
    df = pd.DataFrame(filas)
    df["KEV"] = df["kev"].map(lambda k: "🔥 Sí" if k else "—")
    df = df[["ip", "puerto", "servicio", "cve", "cvss", "severidad", "KEV",
             "aplicabilidad", "requisito", "descripcion"]].rename(columns={
        "ip": "IP", "puerto": "Puerto", "servicio": "Servicio", "cve": "CVE", "cvss": "CVSS",
        "severidad": "Severidad", "aplicabilidad": "Aplicabilidad", "requisito": "Requisito",
        "descripcion": "Descripción",
    })
    a1, a2, a3 = st.columns(3)
    for col, nivel, etiqueta, ayuda in (
        (a1, "Probable", "CVE probables", "Explotable con la configuración por defecto"),
        (a2, "Condicional", "CVE condicionales", "Solo si hay una función concreta activa (IPv6, DNSSEC, TFTP...)"),
        (a3, "Improbable", "CVE improbables", "Requiere un entorno que no corresponde (p. ej. libvirt)"),
    ):
        col.metric(etiqueta, int((df["Aplicabilidad"] == nivel).sum()), help=ayuda)
    g1, g2 = st.columns([1, 2])
    with g1:
        fig = px.histogram(df, x="CVSS", nbins=10, range_x=[0, 10], height=260, title="Distribución CVSS")
        fig.update_layout(margin=dict(t=50, b=10))
        st.plotly_chart(fig, width="stretch")
    with g2:
        solo_kev = st.toggle("Solo explotadas activamente (KEV)", value=False)
        severidades = st.multiselect("Severidad", ["Crítica", "Alta", "Media", "Baja"],
                                     default=["Crítica", "Alta", "Media", "Baja"], key="cve_sev")
        aplicabilidades = st.multiselect("Aplicabilidad", ["Probable", "Condicional", "Improbable"],
                                         default=["Probable", "Condicional"], key="cve_apl")
    df_f = df[df["Severidad"].isin(severidades) & df["Aplicabilidad"].isin(aplicabilidades)]
    if solo_kev:
        df_f = df_f[df_f["KEV"] != "—"]
    df_vista = df_f.copy()
    df_vista["CVE"] = "https://nvd.nist.gov/vuln/detail/" + df_vista["CVE"]
    st.dataframe(df_vista, width="stretch", hide_index=True, column_config={
        "CVE": st.column_config.LinkColumn("CVE", display_text=r"https://nvd\.nist\.gov/vuln/detail/(.*)"),
    })
    st.caption(
        "Ordenados por aplicabilidad y CVSS. La aplicabilidad se deduce de la descripción del NVD "
        "y la versión anunciada puede no reflejar parches retroportados: verifica la configuración real."
    )
    boton_exportar_csv(df_f, "vulnerabilidades_cve.csv", key="csv_cve")


def render() -> None:
    st.header("Descubrimiento y perfilado de dispositivos")
    st.caption("ARP scan + OUI + DNS reverso + DHCP leases + Nmap opcional.")

    iface = interfaz_configurada()
    cidr_default = cidr_de_interfaz(iface) or "192.168.1.0/24"

    col_rango, col_ieee, col_nmap = st.columns([3, 1, 1])
    with col_rango:
        rango_red = st.text_input(
            "Rango de red (CIDR):", value=cidr_default,
            help=f"Derivado de `{iface}`. Editable.",
        )
    with col_ieee:
        usar_ieee = st.toggle("OUI online", value=False, help="Envía el prefijo MAC al proveedor externo.")
    with col_nmap:
        usar_nmap = st.toggle("Nmap -O -sV", value=False, help="Lento: 5-30s/host. Requiere root.")

    if usar_nmap:
        st.warning("⚠️ Nmap activado: el escaneo puede tardar varios minutos.")

    if st.button("▶️ Ejecutar escaneo y perfilado", type="primary"):
        with st.spinner("Sondeando la red..."):
            dispositivos = device_profiler.escanear_y_perfilar(rango_red, usar_nmap, usar_ieee)

        if not dispositivos:
            st.warning(f"No se encontró ningún dispositivo en `{rango_red}`.")
        elif "Error" in dispositivos[0]:
            st.error(dispositivos[0]["Error"])
        else:
            for perfil in dispositivos:
                database.upsert_inventario(perfil)
            st.session_state["_inventario_actual"] = dispositivos
            st.success(f"{len(dispositivos)} dispositivos perfilados y guardados en el inventario.")

    inventario = st.session_state.get("_inventario_actual")
    if not inventario:
        filas_db = database.consultar("SELECT * FROM inventario_red ORDER BY ultima_vez DESC")
        if filas_db:
            inventario = [
                {"ip": f["ip"], "mac": f["mac"], "fabricante": f["fabricante"], "tipo": f["tipo"],
                 "hostname": f["hostname"], "fuente_hostname": f["fuente_hostname"],
                 "os_detectado": f.get("os_detectado"), "puertos_abiertos": f.get("puertos_abiertos"),
                 "servicios": f.get("servicios")}
                for f in filas_db
            ]

    if not inventario:
        st.info("Sin inventario aún. Ejecuta un escaneo para empezar.")
        return

    df = pd.DataFrame(inventario)
    df.columns = [c.replace("_", " ").capitalize() for c in df.columns]

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Hosts en inventario", len(df))
    m2.metric("Tipos distintos", df["Tipo"].nunique() if "Tipo" in df.columns else "—")
    m3.metric("Con hostname", int(df["Hostname"].astype(bool).sum()) if "Hostname" in df.columns else "—")
    m4.metric("Fabricantes únicos", df["Fabricante"].nunique() if "Fabricante" in df.columns else "—")

    if "Tipo" in df.columns:
        st.markdown("#### Distribución por tipo")
        st.bar_chart(df["Tipo"].value_counts())

    st.markdown("#### Inventario")
    f1, f2 = st.columns(2)
    with f1:
        tipos = sorted(df["Tipo"].dropna().unique().tolist()) if "Tipo" in df.columns else []
        filtro_tipo = st.multiselect("Filtrar por tipo", options=tipos, default=tipos)
    with f2:
        filtro_texto = st.text_input("Buscar:", placeholder="IP, MAC, hostname, fabricante...")

    df_f = df.copy()
    if filtro_tipo and "Tipo" in df_f.columns:
        df_f = df_f[df_f["Tipo"].isin(filtro_tipo)]
    if filtro_texto.strip():
        txt = filtro_texto.strip().lower()
        mask = df_f.apply(lambda row: row.astype(str).str.lower().str.contains(txt, regex=False).any(), axis=1)
        df_f = df_f[mask]

    st.dataframe(df_f.reset_index(drop=True), width="stretch")
    st.caption(f"Mostrando {len(df_f)} de {len(df)}.")
    boton_exportar_csv(df_f, "inventario_red.csv")

    st.markdown("---")
    _seccion_cve()
