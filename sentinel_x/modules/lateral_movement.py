"""
Detección de movimiento lateral (tráfico este-oeste).

Dos heurísticas complementarias sobre los eventos capturados por el
sniffer LAN (modules.sniffer.iniciar_sniffer_lan):

  1. Fan-out: un host que contacta a muchos hosts internos distintos en
     poco tiempo. Típico de reconocimiento interno post-explotación
     (T1018 Remote System Discovery, T1046 Network Service Discovery).

  2. Puertos de riesgo: conexiones a puertos administrativos sensibles
     (SMB, RDP, WinRM, SSH, bases de datos) entre hosts internos que no
     son el servidor/controlador de dominio esperado. No se puede saber
     con certeza qué es "esperado" sin contexto, así que se reporta todo
     con conteo de frecuencia para que el analista lo revise.
"""

import ipaddress

import pandas as pd

from core.config import CONFIG
from core.logger import get_logger
from modules import mitre_attack

logger = get_logger("lateral_movement")


def _es_ip_privada(ip: str) -> bool:
    """IP unicast interna. Multicast/broadcast (mDNS, SSDP, ARP-like) no es movimiento lateral."""
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if direccion.is_multicast or direccion.is_unspecified or str(direccion) == "255.255.255.255":
        return False
    return direccion.is_private


def solo_trafico_interno(df: pd.DataFrame) -> pd.DataFrame:
    """Filas con origen y destino internos. Robusto ante DataFrames vacíos (pandas 3)."""
    if df.empty:
        return df
    mascara = df["Origen"].map(_es_ip_privada).astype(bool) & df["Destino"].map(_es_ip_privada).astype(bool)
    return df[mascara]


def _solo_inicios(df: pd.DataFrame) -> pd.DataFrame:
    """
    Se queda con los intentos de conexión (SYN / petición UDP). Sin esto, un
    servidor interno que responde a muchos clientes (gateway, DNS, NAS)
    aparecería como un host haciendo fan-out. Eventos antiguos sin la
    columna "Inicio" se conservan tal cual.
    """
    if "Inicio" not in df.columns:
        return df
    return df[df["Inicio"].fillna(True).astype(bool)]


def detectar_fanout(
    eventos: list[dict],
    umbral_hosts: int = CONFIG["lateral_umbral_fanout"],
    ventana_seg: int = CONFIG["lateral_ventana_seg"],
) -> pd.DataFrame:
    """Hosts que contactaron a más de `umbral_hosts` destinos distintos en la ventana."""
    if not eventos:
        return pd.DataFrame()

    df = pd.DataFrame(eventos)
    if df.empty or not {"Origen", "Destino", "Timestamp"}.issubset(df.columns):
        return pd.DataFrame()

    df = _solo_inicios(df)
    df = solo_trafico_interno(df)
    if df.empty:
        return pd.DataFrame()

    df = df.copy()
    df["ventana"] = (df["Timestamp"] // ventana_seg).astype(int)

    resultados = []
    for (origen, ventana), grupo in df.groupby(["Origen", "ventana"]):
        destinos_unicos = grupo["Destino"].nunique()
        if destinos_unicos >= umbral_hosts:
            info = mitre_attack.info_tecnica("T1046")
            resultados.append({
                "IP origen": origen,
                "Hosts contactados": destinos_unicos,
                "Conexiones totales": len(grupo),
                "Ventana (seg)": ventana_seg,
                "MITRE": "T1046 – Network Service Discovery",
                "Táctica": info["tactica"] if info else "Discovery",
                "Severidad": "Alta" if destinos_unicos >= umbral_hosts * 2 else "Media",
            })

    if not resultados:
        return pd.DataFrame()
    return pd.DataFrame(resultados).sort_values("Hosts contactados", ascending=False).reset_index(drop=True)


def detectar_puertos_riesgo(eventos: list[dict]) -> pd.DataFrame:
    """Conexiones internas a puertos administrativos sensibles."""
    if not eventos:
        return pd.DataFrame()

    df = pd.DataFrame(eventos)
    if df.empty or not {"Origen", "Destino", "Puerto"}.issubset(df.columns):
        return pd.DataFrame()

    df = _solo_inicios(df)
    df = solo_trafico_interno(df)
    puertos_riesgo = CONFIG["lateral_puertos_riesgo"]
    df = df[df["Puerto"].isin(puertos_riesgo.keys())]
    if df.empty:
        return pd.DataFrame()

    mapa_tecnica = {
        445: "T1021.002", 3389: "T1021.001", 5985: "T1021.006", 5986: "T1021.006",
        22: "T1021.004",
    }

    resultados = []
    for (origen, destino, puerto), grupo in df.groupby(["Origen", "Destino", "Puerto"]):
        servicio = puertos_riesgo.get(puerto, str(puerto))
        tecnica_id = mapa_tecnica.get(puerto)
        info = mitre_attack.info_tecnica(tecnica_id) if tecnica_id else None

        resultados.append({
            "IP origen": origen,
            "IP destino": destino,
            "Puerto": puerto,
            "Servicio": servicio,
            "Conexiones": len(grupo),
            "MITRE": f"{tecnica_id} – {info['nombre']}" if info else servicio,
            "Severidad": "Media" if len(grupo) < 5 else "Alta",
        })

    if not resultados:
        return pd.DataFrame()
    return pd.DataFrame(resultados).sort_values("Conexiones", ascending=False).reset_index(drop=True)
