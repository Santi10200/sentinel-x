"""
Pipeline único de análisis.

Toma una foto (snapshot) de todos los buffers compartidos, ejecuta los
detectores, el motor de correlación, la evaluación de postura y la
evaluación NIST CSF 2.0, y devuelve todo en un solo diccionario. Así el
resumen, la vista NIST, los incidentes y el informe muestran exactamente
los mismos datos del mismo instante.
"""

import time

import pandas as pd

from core import database, state
from core.config import CONFIG
from core.logger import get_logger
from modules import (
    beaconing, correlation_engine, lateral_movement, mitre_attack, ml_baseline,
    nist_csf, postura, respuesta_incidentes, threat_intel,
)

logger = get_logger("analisis")

SENSORES = {
    "sniffer_tls": "Sniffer TLS",
    "sniffer_lan": "Sniffer LAN",
    "suricata_tail": "Suricata",
    "zeek_watch": "Zeek",
}


def inventario_persistido() -> list[dict]:
    return database.consultar("SELECT * FROM inventario_red ORDER BY ip")


def redes_wifi_actuales() -> list[dict]:
    """Redes en memoria (sesión actual) o, si no hay, las persistidas."""
    redes = list(state.snapshot_dict(state.redes_wifi, state.lock_redes_wifi).values())
    return redes or database.consultar("SELECT * FROM redes_wifi")


def casos_con_actividad() -> list[dict]:
    casos = respuesta_incidentes.listar_casos()
    conteo = {
        f["caso_id"]: f["n"]
        for f in database.consultar("SELECT caso_id, COUNT(*) AS n FROM casos_historial GROUP BY caso_id")
    }
    for caso in casos:
        caso["num_notas"] = conteo.get(caso["id"], 0)
    return casos


def autoevaluacion_guardada() -> dict[str, str]:
    return {f["subcategoria"]: f["estado"] for f in database.consultar(
        "SELECT subcategoria, estado FROM nist_autoevaluacion"
    )}


def guardar_autoevaluacion(subcategoria: str, estado: str, nota: str = "") -> None:
    if subcategoria not in nist_csf.MANUALES:
        raise ValueError(f"Subcategoría no evaluable manualmente: {subcategoria}")
    if estado not in nist_csf.ESTADOS_MANUALES + [nist_csf.SIN_DATOS]:
        raise ValueError(f"Estado no válido: {estado}")
    database.ejecutar("""
        INSERT INTO nist_autoevaluacion (subcategoria, estado, nota, actualizado)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(subcategoria) DO UPDATE SET
            estado=excluded.estado, nota=excluded.nota, actualizado=excluded.actualizado
    """, (subcategoria, estado, nota, time.time()))


def ejecutar_analisis() -> dict:
    """Ejecuta todos los detectores sobre una foto consistente de los buffers."""
    inicio = time.time()
    flujos_tls = state.snapshot(state.flujos_tls, state.lock_flujos_tls)
    eventos_lan = state.snapshot(state.eventos_lan, state.lock_eventos_lan)
    alertas = state.snapshot(state.alertas_ids, state.lock_alertas)
    inventario = inventario_persistido()
    redes_wifi = redes_wifi_actuales()

    df_beacons = beaconing.detectar(flujos_tls)
    df_fanout = lateral_movement.detectar_fanout(eventos_lan)
    df_puertos = lateral_movement.detectar_puertos_riesgo(eventos_lan)
    df_ml = ml_baseline.detectar_anomalias(eventos_lan or flujos_tls)
    incidentes = correlation_engine.correlacionar(
        df_beacons, df_fanout, df_puertos, df_ml, list(alertas)[-200:]
    )
    df_postura = postura.evaluar(inventario, eventos_lan, redes_wifi)

    resultado = {
        "timestamp": inicio,
        "flujos_tls": flujos_tls,
        "eventos_lan": eventos_lan,
        "alertas": alertas,
        "inventario": inventario,
        "redes_wifi": redes_wifi,
        "df_beacons": df_beacons,
        "df_fanout": df_fanout,
        "df_puertos": df_puertos,
        "df_ml": df_ml,
        "incidentes": incidentes,
        "df_postura": df_postura,
    }
    resultado.update(evaluar_nist(resultado))
    logger.info("Análisis completo en %.2fs: %d incidentes, %d hallazgos de postura.",
                time.time() - inicio, len(incidentes), len(df_postura))
    return resultado


def evaluar_nist(resultado: dict) -> dict:
    """Re-evalúa solo NIST (barato): útil tras abrir casos o autoevaluar."""
    stats_ti = threat_intel.estadisticas_feeds()
    inventario = resultado["inventario"]
    ultima_vez = max((h.get("ultima_vez") or 0 for h in inventario), default=None) or None
    ctx = nist_csf.Contexto(
        sensores={etiqueta: bool(state.estado_hilos.get(clave, {}).get("activo"))
                  for clave, etiqueta in SENSORES.items()},
        inventario=inventario,
        inventario_ultima_vez=ultima_vez,
        eventos_lan=len(resultado["eventos_lan"]),
        flujos_tls=len(resultado["flujos_tls"]),
        alertas_ids=len(resultado["alertas"]),
        ti_habilitado=CONFIG["ti_habilitado"],
        ti_indicadores=stats_ti["ips_maliciosas"] + stats_ti["dominios_maliciosos"],
        mitre_tecnicas=mitre_attack.num_tecnicas_cargadas(),
        analisis_ejecutado=True,
        incidentes=resultado["incidentes"],
        postura=resultado["df_postura"],
        redes_wifi=resultado["redes_wifi"],
        casos=casos_con_actividad(),
        autoevaluacion=autoevaluacion_guardada(),
    )
    df_nist = nist_csf.evaluar(ctx)
    df_puntos = nist_csf.puntuaciones(df_nist)
    return {
        "df_nist": df_nist,
        "df_nist_puntos": df_puntos,
        "nist_global": nist_csf.puntuacion_global(df_puntos),
        "casos": ctx.casos,
    }


def conteo_por_severidad(incidentes: list[dict], df_postura: pd.DataFrame) -> pd.DataFrame:
    filas = []
    for sev in ("Crítica", "Alta", "Media", "Baja"):
        filas.append({"Severidad": sev, "Origen": "Incidentes",
                      "Cantidad": sum(1 for i in incidentes if i["severidad"] == sev)})
        n_post = int((df_postura["Severidad"] == sev).sum()) if not df_postura.empty else 0
        filas.append({"Severidad": sev, "Origen": "Postura", "Cantidad": n_post})
    return pd.DataFrame(filas)
