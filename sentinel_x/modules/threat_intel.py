"""
Módulo de Threat Intelligence.

Fuentes usadas (todas gratuitas, sin API key, aptas para laboratorio):
  - Feodo Tracker (abuse.ch): IPs de servidores C2 conocidos (Emotet, Dridex, etc.)
  - URLhaus (abuse.ch): dominios/URLs maliciosos recientes
  - CISA KEV: catálogo de vulnerabilidades explotadas activamente (no es IOC,
    pero permite avisar si un puerto/servicio detectado corresponde a un CVE
    con explotación activa conocida)

Arquitectura: un hilo de fondo refresca los feeds cada `ti_actualizacion_seg`
y los guarda en sets en memoria + cache con TTL en core.state.ti_cache.
Las consultas de "¿es esta IP maliciosa?" son O(1) contra esos sets, nunca
hacen red en el camino caliente del sniffer.
"""

import csv
import io
import json
import threading
import time
import urllib.request

from core.config import CONFIG
from core.logger import get_logger
from core import state

logger = get_logger("threat_intel")

# Sets en memoria, protegidos por state.lock_ti_cache
_ips_maliciosas: set[str] = set()
_dominios_maliciosos: set[str] = set()
_cves_explotados_activamente: set[str] = set()


def _descargar_json(url: str, timeout: int) -> dict | list | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Sentinel-X/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:
        logger.warning("Fallo descargando %s: %s", url, exc)
        return None


def _descargar_texto(url: str, timeout: int) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Sentinel-X/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode(errors="ignore")
    except Exception as exc:
        logger.warning("Fallo descargando %s: %s", url, exc)
        return None


def _actualizar_feodo() -> set[str]:
    """Feodo Tracker: lista de IPs de servidores C2 botnet activos."""
    data = _descargar_json(CONFIG["ti_feodo_url"], CONFIG["ti_timeout_seg"])
    if not data:
        return set()
    ips = set()
    for entrada in data:
        ip = entrada.get("ip_address") if isinstance(entrada, dict) else None
        if ip:
            ips.add(ip)
    logger.info("Feodo Tracker: %d IPs C2 cargadas.", len(ips))
    return ips


def _actualizar_urlhaus() -> set[str]:
    """URLhaus: dominios/hosts maliciosos recientes (CSV)."""
    texto = _descargar_texto(CONFIG["ti_urlhaus_url"], CONFIG["ti_timeout_seg"])
    if not texto:
        return set()
    dominios = set()
    try:
        lineas = [l for l in texto.splitlines() if l and not l.startswith("#")]
        lector = csv.reader(lineas)
        for fila in lector:
            if len(fila) > 2:
                url = fila[2].strip('"')
                host = url.split("/")[2] if "://" in url else url
                host = host.split(":")[0]
                if host:
                    dominios.add(host.lower())
    except Exception as exc:
        logger.warning("Error parseando URLhaus: %s", exc)
    logger.info("URLhaus: %d dominios maliciosos cargados.", len(dominios))
    return dominios


def _actualizar_kev() -> set[str]:
    """CISA KEV: CVEs con explotación activa conocida."""
    data = _descargar_json(CONFIG["ti_kev_url"], CONFIG["ti_timeout_seg"])
    if not data:
        return set()
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    cves = {v.get("cveID") for v in vulns if v.get("cveID")}
    logger.info("CISA KEV: %d CVEs con explotación activa.", len(cves))
    return cves


def actualizar_feeds() -> None:
    """Descarga y reemplaza todos los feeds. Pensado para correr en background."""
    global _ips_maliciosas, _dominios_maliciosos, _cves_explotados_activamente
    if not CONFIG["ti_habilitado"]:
        return

    nuevas_ips = _actualizar_feodo()
    nuevos_dominios = _actualizar_urlhaus()
    nuevos_cves = _actualizar_kev()

    with state.lock_ti_cache:
        if nuevas_ips:
            _ips_maliciosas = nuevas_ips
        if nuevos_dominios:
            _dominios_maliciosos = nuevos_dominios
        if nuevos_cves:
            _cves_explotados_activamente = nuevos_cves

        state.estado_hilos["ti_updater"]["ultima_actualizacion"] = time.time()


def verificar_ip(ip: str) -> dict | None:
    """Devuelve {'malicioso': True, 'fuente': 'Feodo Tracker'} o None si está limpia."""
    with state.lock_ti_cache:
        if ip in _ips_maliciosas:
            return {"malicioso": True, "fuente": "Feodo Tracker (C2 botnet)"}
    return None


def verificar_dominio(dominio: str) -> dict | None:
    """Devuelve hit de URLhaus si el dominio/SNI coincide."""
    if not dominio:
        return None
    dominio = dominio.lower()
    with state.lock_ti_cache:
        for malo in _dominios_maliciosos:
            if dominio == malo or dominio.endswith("." + malo):
                return {"malicioso": True, "fuente": "URLhaus (malware/phishing)"}
    return None


def cve_con_explotacion_activa(cve: str) -> bool:
    with state.lock_ti_cache:
        return cve.upper() in _cves_explotados_activamente


def estadisticas_feeds() -> dict:
    with state.lock_ti_cache:
        return {
            "ips_maliciosas": len(_ips_maliciosas),
            "dominios_maliciosos": len(_dominios_maliciosos),
            "cves_kev": len(_cves_explotados_activamente),
            "ultima_actualizacion": state.estado_hilos["ti_updater"]["ultima_actualizacion"],
        }


def hilo_actualizador_ti() -> None:
    """Hilo de fondo: refresca los feeds periódicamente mientras la app viva."""
    if not CONFIG["ti_habilitado"]:
        return
    state.estado_hilos["ti_updater"]["activo"] = True
    while True:
        try:
            actualizar_feeds()
        except Exception as exc:
            logger.error("Error en hilo actualizador de TI: %s", exc)
            state.estado_hilos["ti_updater"]["error"] = str(exc)
        time.sleep(CONFIG["ti_actualizacion_seg"])
