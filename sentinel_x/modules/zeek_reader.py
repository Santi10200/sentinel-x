"""
Lector de logs Zeek en formato JSON.

Zeek, configurado en modo JSON (redef LogAscii::use_json = T;), escribe
un archivo por tipo de log dentro de logs/current/ (conn.log, dns.log,
ssl.log, http.log, files.log, etc.), cada uno JSON-lines.

Este módulo sigue varios de esos archivos simultáneamente con la misma
estrategia de offset que usa el lector de Suricata (no se reimplementa
con watchdog/inotify para mantener una sola dependencia menos; el costo
de un poll cada 2s sobre ~6 archivos es despreciable).
"""

import json
import os
import time

from core.config import CONFIG
from core.logger import get_logger
from core import state

logger = get_logger("zeek_reader")

# Logs de Zeek más relevantes para seguridad. Cada uno tiene su propio
# esquema de columnas; se extraen solo los campos más útiles para no
# acoplar el dashboard a la totalidad del esquema Zeek.
_LOGS_RELEVANTES = {
    "conn.log": ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                 "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state"],
    "dns.log": ["ts", "id.orig_h", "id.resp_h", "query", "qtype_name", "answers", "rcode_name"],
    "ssl.log": ["ts", "id.orig_h", "id.resp_h", "server_name", "version",
                "cipher", "validation_status", "subject"],
    "http.log": ["ts", "id.orig_h", "id.resp_h", "method", "host", "uri",
                 "status_code", "user_agent"],
    "files.log": ["ts", "tx_hosts", "rx_hosts", "filename", "mime_type", "md5", "sha1"],
    "notice.log": ["ts", "id.orig_h", "id.resp_h", "note", "msg"],
}


def _extraer_campo(evento: dict, ruta_campo: str):
    """Soporta rutas anidadas tipo 'id.orig_h' -> evento['id']['orig_h']."""
    partes = ruta_campo.split(".")
    valor = evento
    for parte in partes:
        if isinstance(valor, dict):
            valor = valor.get(parte)
        else:
            return None
    return valor


def _procesar_linea(tipo_log: str, linea: str) -> dict | None:
    linea = linea.strip()
    if not linea:
        return None
    try:
        evento = json.loads(linea)
    except json.JSONDecodeError:
        return None

    campos = _LOGS_RELEVANTES.get(tipo_log, [])
    registro = {"tipo_log": tipo_log.replace(".log", ""), "timestamp_local": time.time()}
    for campo in campos:
        registro[campo] = _extraer_campo(evento, campo)
    return registro


def hilo_watch_zeek() -> None:
    """
    Hilo de fondo: sigue todos los logs relevantes de Zeek en paralelo
    usando un offset por archivo. Tolera que algunos logs no existan
    (no todos los entornos tienen tráfico HTTP, por ejemplo).
    """
    directorio = CONFIG["dir_zeek_logs"]
    state.estado_hilos["zeek_watch"]["activo"] = True
    state.estado_hilos["zeek_watch"]["error"] = None

    if not os.path.isdir(directorio):
        msg = f"Directorio Zeek no encontrado: {directorio}"
        logger.warning(msg)
        state.estado_hilos["zeek_watch"]["error"] = msg
        state.estado_hilos["zeek_watch"]["activo"] = False
        return

    offsets: dict[str, int] = {}
    logger.info("Watch de logs Zeek iniciado en %s.", directorio)

    while True:
        try:
            for tipo_log in _LOGS_RELEVANTES:
                ruta = os.path.join(directorio, tipo_log)
                if not os.path.exists(ruta):
                    continue

                tamano_actual = os.path.getsize(ruta)
                offset_previo = offsets.get(tipo_log, 0)

                if tamano_actual < offset_previo:
                    offset_previo = 0  # rotación de log

                if tamano_actual > offset_previo:
                    with open(ruta, "r", encoding="utf-8") as f:
                        f.seek(offset_previo)
                        for linea in f:
                            registro = _procesar_linea(tipo_log, linea)
                            if registro:
                                with state.lock_zeek:
                                    state.eventos_zeek.append(registro)
                                    state.estado_hilos["zeek_watch"]["procesados"] += 1
                        offsets[tipo_log] = f.tell()

            time.sleep(2)
        except Exception as exc:
            logger.error("Error en watch de Zeek: %s", exc)
            state.estado_hilos["zeek_watch"]["error"] = str(exc)
            time.sleep(5)
