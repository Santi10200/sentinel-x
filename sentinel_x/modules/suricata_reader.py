"""
Lector de eve.json de Suricata.

A diferencia de una lectura completa bajo demanda (costosa en archivos
grandes), este módulo hace 'tail -F' real: recuerda el offset de byte
hasta donde leyó y solo procesa las líneas nuevas. Corre como hilo daemon
y empuja cada alerta nueva al buffer compartido, enriquecida con el
mapeo a MITRE ATT&CK y el cruce contra Threat Intelligence.
"""

import json
import os
import time

from core.config import CONFIG
from core.logger import get_logger
from core import state, database
from modules import mitre_attack, threat_intel

logger = get_logger("suricata_reader")


def _procesar_linea(linea: str) -> dict | None:
    linea = linea.strip()
    if not linea:
        return None
    try:
        evento = json.loads(linea)
    except json.JSONDecodeError:
        return None

    if evento.get("event_type") != "alert":
        return None

    alerta = evento.get("alert", {})
    tecnicas = mitre_attack.extraer_tecnicas_de_alerta_suricata(evento)
    tecnica_principal = tecnicas[0] if tecnicas else None
    info_mitre = mitre_attack.info_tecnica(tecnica_principal) if tecnica_principal else None

    ip_origen = evento.get("src_ip", "")
    ip_destino = evento.get("dest_ip", "")
    hit_ti_origen = threat_intel.verificar_ip(ip_origen)
    hit_ti_destino = threat_intel.verificar_ip(ip_destino)

    return {
        "Fecha/Hora": evento.get("timestamp", "")[:19],
        "IP Origen": ip_origen,
        "Puerto Origen": evento.get("src_port", ""),
        "IP Destino": ip_destino,
        "Puerto Destino": evento.get("dest_port", ""),
        "Proto": evento.get("proto", ""),
        "Gravedad": alerta.get("severity", 3),
        "Categoría": alerta.get("category", "Desconocido"),
        "Firma": alerta.get("signature", "Desconocido"),
        "MITRE Técnica": tecnica_principal or "",
        "MITRE Nombre": info_mitre["nombre"] if info_mitre else "",
        "MITRE Táctica": info_mitre["tactica"] if info_mitre else "",
        "TI Origen malicioso": hit_ti_origen["fuente"] if hit_ti_origen else "",
        "TI Destino malicioso": hit_ti_destino["fuente"] if hit_ti_destino else "",
        "Timestamp": time.time(),
    }


def leer_snapshot_completo() -> list[dict]:
    """Lectura completa bajo demanda (para el botón 'recargar histórico')."""
    ruta = CONFIG["archivo_suricata"]
    if not os.path.exists(ruta):
        return []
    alertas = []
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            for linea in f:
                procesada = _procesar_linea(linea)
                if procesada:
                    alertas.append(procesada)
    except OSError as exc:
        logger.error("Error leyendo eve.json: %s", exc)
    return alertas


def hilo_tail_suricata() -> None:
    """Hilo de fondo: sigue el archivo eve.json y procesa solo líneas nuevas."""
    ruta = CONFIG["archivo_suricata"]
    state.estado_hilos["suricata_tail"]["activo"] = True
    state.estado_hilos["suricata_tail"]["error"] = None

    if os.path.exists(ruta):
        offset = os.path.getsize(ruta)  # arranca desde el final, no reprocesa histórico
    else:
        # Suricata puede arrancar después que Sentinel-X: se espera al archivo en vez
        # de abandonar, y todo lo que escriba a partir de entonces es nuevo.
        msg = f"Esperando a {ruta} (¿Suricata en marcha?)"
        logger.warning(msg)
        state.estado_hilos["suricata_tail"]["error"] = msg
        while not os.path.exists(ruta):
            time.sleep(5)
        state.estado_hilos["suricata_tail"]["error"] = None
        offset = 0
    logger.info("Tail de Suricata iniciado en %s (offset inicial: %d).", ruta, offset)

    while True:
        try:
            tamano_actual = os.path.getsize(ruta)
            if tamano_actual < offset:
                # El archivo fue rotado/truncado externamente (logrotate)
                offset = 0

            if tamano_actual > offset:
                with open(ruta, "r", encoding="utf-8") as f:
                    f.seek(offset)
                    for linea in f:
                        procesada = _procesar_linea(linea)
                        if procesada:
                            with state.lock_alertas:
                                state.alertas_ids.append(procesada)
                                state.registrar_evento("suricata_tail")
                            database.insertar("alertas_ids", {
                                "timestamp": procesada["Timestamp"], "fecha_hora": procesada["Fecha/Hora"],
                                "ip_origen": procesada["IP Origen"], "ip_destino": procesada["IP Destino"],
                                "gravedad": procesada["Gravedad"], "categoria": procesada["Categoría"],
                                "firma": procesada["Firma"], "mitre_tactica": procesada["MITRE Táctica"],
                                "mitre_tecnica": procesada["MITRE Técnica"],
                            })
                    offset = f.tell()

            time.sleep(2)
        except Exception as exc:
            logger.error("Error en tail de Suricata: %s", exc)
            state.estado_hilos["suricata_tail"]["error"] = str(exc)
            time.sleep(5)
