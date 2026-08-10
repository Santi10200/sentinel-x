"""
Motor de correlación.

Cada módulo de detección (beaconing, movimiento lateral, baseline ML,
alertas IDS) produce hallazgos de forma independiente. Este motor los
toma a todos y construye una vista unificada de "incidentes": agrupa
hallazgos que comparten una IP, ordena por severidad combinada, y anota
qué fuentes corroboran cada incidente.

Un incidente que aparece en 2+ módulos distintos (ej. beaconing +
alerta IDS sobre la misma IP) tiene mucha más confianza que uno que
solo una fuente reporta, así que la severidad sube con cada fuente
adicional que corrobora.
"""

import time

import pandas as pd

from core.logger import get_logger

logger = get_logger("correlation_engine")

_PESO_SEVERIDAD = {"Crítica": 4, "Alta": 3, "Media": 2, "Baja": 1}
_SEVERIDAD_INVERSA = {v: k for k, v in _PESO_SEVERIDAD.items()}


def _extraer_ips_de_fila(fila: dict, columnas_ip: list[str]) -> set[str]:
    return {fila[c] for c in columnas_ip if c in fila and fila[c]}


def correlacionar(
    df_beacons: pd.DataFrame,
    df_fanout: pd.DataFrame,
    df_puertos_riesgo: pd.DataFrame,
    df_anomalias_ml: pd.DataFrame,
    alertas_ids_recientes: list[dict],
) -> list[dict]:
    """
    Construye una lista de incidentes unificados. Cada incidente:
        {ip_principal, severidad, peso, fuentes: [...], descripcion, mitre_tecnicas, timestamp}
    """
    hallazgos_por_ip: dict[str, list[dict]] = {}

    def _registrar(ip: str, fuente: str, severidad: str, descripcion: str, mitre: str = ""):
        if not ip:
            return
        hallazgos_por_ip.setdefault(ip, []).append({
            "fuente": fuente, "severidad": severidad,
            "descripcion": descripcion, "mitre": mitre,
        })

    if not df_beacons.empty:
        for _, fila in df_beacons.iterrows():
            _registrar(
                fila.get("IP Destino", ""), "Beaconing C2", fila.get("Severidad", "Media"),
                f"Beacon hacia {fila.get('Destino (SNI)', '?')} ({fila.get('Razones', '')})",
            )

    if not df_fanout.empty:
        for _, fila in df_fanout.iterrows():
            _registrar(
                fila.get("IP origen", ""), "Movimiento lateral (fan-out)", fila.get("Severidad", "Media"),
                f"Contactó {fila.get('Hosts contactados', '?')} hosts internos en {fila.get('Ventana (seg)', '?')}s",
                fila.get("MITRE", ""),
            )

    if not df_puertos_riesgo.empty:
        for _, fila in df_puertos_riesgo.iterrows():
            _registrar(
                fila.get("IP origen", ""), "Movimiento lateral (puerto sensible)", fila.get("Severidad", "Media"),
                f"{fila.get('Conexiones', '?')} conexiones a {fila.get('Servicio', '?')} en {fila.get('IP destino', '?')}",
                fila.get("MITRE", ""),
            )

    if not df_anomalias_ml.empty:
        for _, fila in df_anomalias_ml.iterrows():
            _registrar(
                fila.get("Host", ""), "Baseline ML", fila.get("Severidad", "Media"),
                f"Comportamiento anómalo respecto al histórico (score={fila.get('Score anomalía', '?')})",
            )

    for alerta in alertas_ids_recientes:
        severidad_map = {1: "Crítica", 2: "Alta", 3: "Media"}
        severidad = severidad_map.get(alerta.get("Gravedad", 3), "Media")
        ip_origen = alerta.get("IP Origen", "")
        _registrar(
            ip_origen, "Suricata IDS", severidad,
            alerta.get("Firma", "Alerta IDS"),
            alerta.get("MITRE Técnica", ""),
        )

    incidentes = []
    for ip, hallazgos in hallazgos_por_ip.items():
        peso_max = max(_PESO_SEVERIDAD.get(h["severidad"], 1) for h in hallazgos)
        # Bonus de confianza: +1 de peso por cada fuente adicional que corrobora,
        # tope en severidad "Crítica" (peso 4).
        fuentes_unicas = {h["fuente"] for h in hallazgos}
        peso_final = min(4, peso_max + (len(fuentes_unicas) - 1))

        incidentes.append({
            "ip_principal": ip,
            "severidad": _SEVERIDAD_INVERSA[peso_final],
            "peso": peso_final,
            "num_fuentes": len(fuentes_unicas),
            "fuentes": sorted(fuentes_unicas),
            "hallazgos": hallazgos,
            "mitre_tecnicas": sorted({h["mitre"] for h in hallazgos if h["mitre"]}),
            "timestamp": time.time(),
        })

    incidentes.sort(key=lambda x: (-x["peso"], -x["num_fuentes"]))
    return incidentes


def resumen_a_dataframe(incidentes: list[dict]) -> pd.DataFrame:
    """Vista tabular plana para mostrar en la UI."""
    if not incidentes:
        return pd.DataFrame()

    filas = []
    for inc in incidentes:
        filas.append({
            "IP": inc["ip_principal"],
            "Severidad": inc["severidad"],
            "Fuentes que corroboran": inc["num_fuentes"],
            "Detectado por": ", ".join(inc["fuentes"]),
            "Técnicas MITRE": ", ".join(inc["mitre_tecnicas"]) or "—",
            "Resumen": " | ".join(h["descripcion"] for h in inc["hallazgos"][:3]),
        })
    return pd.DataFrame(filas)
