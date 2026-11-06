"""Correlación temporal y por entidad para los hallazgos de Sentinel-X.

Un incidente representa un episodio sobre un activo, no todas las señales que
alguna vez compartieron una IP. Solo familias de detección independientes
elevan la severidad; dos reglas de movimiento lateral no simulan dos sensores.
"""

from __future__ import annotations

import math
import time
from collections.abc import Iterable
from datetime import datetime
from typing import Any

import pandas as pd

from core.config import CONFIG
from core.logger import get_logger

logger = get_logger("correlation_engine")

_PESO_SEVERIDAD = {"Crítica": 4, "Alta": 3, "Media": 2, "Baja": 1}
_SEVERIDAD_INVERSA = {v: k for k, v in _PESO_SEVERIDAD.items()}


def _timestamp(valor: Any) -> float | None:
    if valor is None or valor == "":
        return None
    try:
        numero = float(valor)
        return numero if math.isfinite(numero) and numero > 0 else None
    except (TypeError, ValueError):
        pass
    if isinstance(valor, str):
        try:
            return datetime.fromisoformat(valor.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _registrar(destino: dict[str, list[dict]], ip: str, fuente: str, familia: str,
               severidad: str, descripcion: str, mitre: str = "", timestamp: Any = None) -> None:
    if not ip:
        return
    destino.setdefault(str(ip), []).append({
        "fuente": fuente, "familia": familia,
        "severidad": severidad if severidad in _PESO_SEVERIDAD else "Media",
        "descripcion": descripcion, "mitre": mitre, "timestamp": _timestamp(timestamp),
    })


def _episodios(hallazgos: Iterable[dict], ventana_seg: int) -> list[list[dict]]:
    """Divide señales del activo en episodios separados por la ventana temporal."""
    ordenados = sorted(hallazgos, key=lambda h: h["timestamp"] if h["timestamp"] is not None else -1)
    episodios: list[list[dict]] = []
    ultimo_ts: float | None = None
    for hallazgo in ordenados:
        ts = hallazgo["timestamp"]
        nuevo = bool(ts is not None and ultimo_ts is not None and ts - ultimo_ts > ventana_seg)
        if nuevo or not episodios:
            episodios.append([])
        episodios[-1].append(hallazgo)
        if ts is not None:
            ultimo_ts = ts
    return episodios


def _confianza(hallazgos: list[dict]) -> tuple[int, str]:
    familias = {h["familia"] for h in hallazgos}
    fuentes = {h["fuente"] for h in hallazgos}
    puntaje = min(100, 25 + 30 * len(familias) + 5 * max(0, len(fuentes) - len(familias)))
    etiqueta = "Alta" if len(familias) >= 3 else "Media" if len(familias) >= 2 else "Inicial"
    return puntaje, etiqueta


def _incidente(ip: str, hallazgos: list[dict], ahora: float) -> dict:
    peso_max = max(_PESO_SEVERIDAD[h["severidad"]] for h in hallazgos)
    familias = {h["familia"] for h in hallazgos}
    peso_final = min(4, peso_max + len(familias) - 1)
    timestamps = [h["timestamp"] for h in hallazgos if h["timestamp"] is not None]
    inicio, fin = (min(timestamps), max(timestamps)) if timestamps else (None, None)
    confianza, nivel_confianza = _confianza(hallazgos)
    return {
        "ip_principal": ip, "severidad": _SEVERIDAD_INVERSA[peso_final], "peso": peso_final,
        "num_fuentes": len(familias), "fuentes": sorted({h["fuente"] for h in hallazgos}),
        "familias": sorted(familias), "hallazgos": hallazgos,
        "mitre_tecnicas": sorted({h["mitre"] for h in hallazgos if h["mitre"]}),
        "ventana_inicio": inicio, "ventana_fin": fin,
        "edad_segundos": max(0.0, ahora - fin) if fin is not None else None,
        "confianza": confianza, "nivel_confianza": nivel_confianza, "timestamp": fin or ahora,
    }


def correlacionar(
    df_beacons: pd.DataFrame, df_fanout: pd.DataFrame, df_puertos_riesgo: pd.DataFrame,
    df_anomalias_ml: pd.DataFrame, alertas_ids_recientes: list[dict], *,
    ahora: float | None = None, ventana_seg: int = CONFIG["correlacion_ventana_seg"],
) -> list[dict]:
    """Construye incidentes por IP y episodio temporal a partir de los detectores."""
    ahora = time.time() if ahora is None else ahora
    hallazgos_por_ip: dict[str, list[dict]] = {}

    for _, fila in df_beacons.iterrows() if not df_beacons.empty else []:
        _registrar(hallazgos_por_ip, fila.get("IP Local", ""), "Beaconing C2", "Beaconing C2",
                   fila.get("Severidad", "Media"),
                   f"Beacon hacia {fila.get('Destino (SNI)', '?')} [{fila.get('IP Destino', '?')}] ({fila.get('Razones', '')})",
                   "T1071.001", fila.get("Último evento"))
    for _, fila in df_fanout.iterrows() if not df_fanout.empty else []:
        _registrar(hallazgos_por_ip, fila.get("IP origen", ""), "Movimiento lateral (fan-out)", "Movimiento lateral",
                   fila.get("Severidad", "Media"),
                   f"Contactó {fila.get('Hosts contactados', '?')} hosts internos en {fila.get('Ventana (seg)', '?')}s",
                   fila.get("MITRE", ""), fila.get("Fin ventana"))
    for _, fila in df_puertos_riesgo.iterrows() if not df_puertos_riesgo.empty else []:
        _registrar(hallazgos_por_ip, fila.get("IP origen", ""), "Movimiento lateral (puerto sensible)", "Movimiento lateral",
                   fila.get("Severidad", "Media"),
                   f"{fila.get('Conexiones', '?')} conexiones a {fila.get('Servicio', '?')} en {fila.get('IP destino', '?')}",
                   fila.get("MITRE", ""), fila.get("Último evento"))
    for _, fila in df_anomalias_ml.iterrows() if not df_anomalias_ml.empty else []:
        _registrar(hallazgos_por_ip, fila.get("Host", ""), "Baseline ML", "Baseline ML",
                   fila.get("Severidad", "Media"),
                   f"Comportamiento anómalo respecto al histórico (score={fila.get('Score anomalía', '?')})",
                   "", fila.get("Timestamp") or fila.get("Minuto"))
    for alerta in alertas_ids_recientes:
        severidad = {1: "Crítica", 2: "Alta", 3: "Media"}.get(alerta.get("Gravedad", 3), "Media")
        _registrar(hallazgos_por_ip, alerta.get("IP Origen", ""), "Suricata IDS", "Suricata IDS",
                   severidad, alerta.get("Firma", "Alerta IDS"), alerta.get("MITRE Técnica", ""), alerta.get("Timestamp"))

    incidentes = [
        _incidente(ip, episodio, ahora)
        for ip, hallazgos in hallazgos_por_ip.items()
        for episodio in _episodios(hallazgos, max(1, int(ventana_seg)))
    ]
    incidentes.sort(key=lambda x: (-x["peso"], -x["confianza"], -x["timestamp"]))
    return incidentes


def resumen_a_dataframe(incidentes: list[dict]) -> pd.DataFrame:
    """Vista plana con prioridad, confianza y frescura para operación."""
    if not incidentes:
        return pd.DataFrame()
    filas = []
    for inc in incidentes:
        edad = "Sin marca temporal" if inc["edad_segundos"] is None else f"{inc['edad_segundos']:.0f}s"
        filas.append({
            "IP": inc["ip_principal"], "Severidad": inc["severidad"],
            "Confianza": f"{inc['confianza']}% ({inc['nivel_confianza']})", "Antigüedad": edad,
            "Fuentes que corroboran": inc["num_fuentes"], "Detectado por": ", ".join(inc["fuentes"]),
            "Técnicas MITRE": ", ".join(inc["mitre_tecnicas"]) or "—",
            "Resumen": " | ".join(h["descripcion"] for h in inc["hallazgos"][:3]),
        })
    return pd.DataFrame(filas)
