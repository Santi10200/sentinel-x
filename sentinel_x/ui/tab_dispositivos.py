"""Pestaña 3: Descubrimiento y perfilado de dispositivos."""

import pandas as pd
import streamlit as st

from core import database
from core.network_iface import cidr_de_interfaz, interfaz_configurada
from modules import device_profiler
from ui.helpers import boton_exportar_csv


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
        mask = df_f.apply(lambda row: row.astype(str).str.lower().str.contains(txt).any(), axis=1)
        df_f = df_f[mask]

    st.dataframe(df_f.reset_index(drop=True), use_container_width=True)
    st.caption(f"Mostrando {len(df_f)} de {len(df)}.")
    boton_exportar_csv(df_f, "inventario_red.csv")
