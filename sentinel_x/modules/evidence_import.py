"""Importación local, limitada y trazable de evidencias Zeek JSON-lines.

No replica RITA, Arkime ni Zeek. Toma únicamente una decisión de diseño útil
para Sentinel-X: una captura histórica debe pasar por la misma normalización y
análisis que el tráfico en vivo, dejando un manifiesto verificable sin guardar
copias innecesarias de datos sensibles.
"""

import hashlib
import os
import time

from core import database, state
from core.config import CONFIG
from modules import zeek_reader

LOGS_ADMITIDOS = frozenset(zeek_reader._LOGS_RELEVANTES)
_MAX_LINEA_BYTES = 1024 * 1024


def _numero(valor, predeterminado=0.0) -> float:
    try:
        return float(valor)
    except (TypeError, ValueError):
        return predeterminado


def _evento_lan_desde_conn(registro: dict) -> dict | None:
    """Convierte un conn.log normalizado al contrato interno de eventos LAN."""
    origen = registro.get("id.orig_h")
    destino = registro.get("id.resp_h")
    if not origen or not destino:
        return None
    puerto = registro.get("id.resp_p")
    try:
        puerto = int(puerto) if puerto is not None else 0
    except (TypeError, ValueError):
        puerto = 0
    return {
        "Origen": origen,
        "Destino": destino,
        "Puerto": puerto,
        "Puerto origen": registro.get("id.orig_p") or 0,
        "Proto": str(registro.get("proto") or "desconocido").upper(),
        "Inicio": True,
        "Timestamp": _numero(registro.get("ts"), time.time()),
        "Tamaño (bytes)": _numero(registro.get("orig_bytes")) + _numero(registro.get("resp_bytes")),
        "Fuente": "evidencia_zeek",
    }


def importar_zeek_jsonl(nombre_archivo: str, contenido: bytes, *, persistir: bool = True) -> dict:
    """Ingresa un único log Zeek JSON-lines y retorna su manifiesto.

    El nombre se limita a logs conocidos; el contenido no se escribe a disco.
    Las líneas inválidas se cuentan y no pueden detener el resto del análisis.
    """
    archivo = os.path.basename(nombre_archivo or "")
    if archivo not in LOGS_ADMITIDOS:
        raise ValueError(f"Log Zeek no admitido: {archivo or 'sin nombre'}")
    if not isinstance(contenido, bytes):
        raise TypeError("La evidencia debe recibirse como bytes")
    limite_bytes = CONFIG["evidencia_max_bytes"]
    if not contenido:
        raise ValueError("La evidencia está vacía")
    if len(contenido) > limite_bytes:
        raise ValueError(f"La evidencia supera el límite de {limite_bytes} bytes")
    try:
        texto = contenido.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("La evidencia Zeek debe estar codificada en UTF-8") from exc

    aceptados = rechazados = lineas = eventos_lan = 0
    limite_eventos = CONFIG["evidencia_max_eventos"]
    for linea in texto.splitlines():
        lineas += 1
        if len(linea.encode("utf-8")) > _MAX_LINEA_BYTES:
            rechazados += 1
            continue
        if aceptados >= limite_eventos:
            rechazados += 1
            continue
        registro = zeek_reader.normalizar_linea(archivo, linea)
        if registro is None:
            rechazados += 1
            continue
        aceptados += 1
        with state.lock_zeek:
            state.eventos_zeek.append(registro)
        if archivo == "conn.log":
            evento_lan = _evento_lan_desde_conn(registro)
            if evento_lan:
                with state.lock_eventos_lan:
                    state.eventos_lan.append(evento_lan)
                eventos_lan += 1

    manifiesto = {
        "timestamp": time.time(),
        "archivo": archivo,
        "tipo_log": archivo.removesuffix(".log"),
        "sha256": hashlib.sha256(contenido).hexdigest(),
        "tamano_bytes": len(contenido),
        "lineas": lineas,
        "aceptados": aceptados,
        "rechazados": rechazados,
        "eventos_lan": eventos_lan,
    }
    if persistir:
        database.registrar_importacion_evidencia({
            campo: manifiesto[campo]
            for campo in ("timestamp", "archivo", "tipo_log", "sha256", "tamano_bytes", "lineas", "aceptados", "rechazados")
        })
    return manifiesto


def importaciones_recientes(limite: int = 20) -> list[dict]:
    """Devuelve manifiestos, nunca contenidos de evidencia."""
    limite = max(1, min(int(limite), 100))
    return database.consultar(
        "SELECT * FROM importaciones_evidencia ORDER BY timestamp DESC LIMIT ?", (limite,)
    )
