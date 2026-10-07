"""Salud operativa del sensor Sentinel-X.

No evalúa seguridad de la red: indica si las fuentes que alimentan las
detecciones están vivas, frescas y con capacidad disponible.
"""

import os
import time

from core import state
from core.config import CONFIG

_FUENTES = {
    "sniffer_tls": "Captura TLS",
    "sniffer_lan": "Captura LAN",
    "sniffer_identidad": "Identidad de activos",
    "suricata_tail": "Suricata",
    "zeek_watch": "Zeek",
    "ti_updater": "Threat Intelligence",
    "ml_baseline": "Baseline ML",
    "sniffer_wifi": "Wi-Fi pasivo",
}


def _edad_texto(segundos: float | None) -> str:
    if segundos is None:
        return "sin eventos aún"
    if segundos < 60:
        return f"hace {int(segundos)} s"
    if segundos < 3600:
        return f"hace {int(segundos // 60)} min"
    return f"hace {int(segundos // 3600)} h"


def _estado_fuente(nombre: str, info: dict, ahora: float) -> dict:
    if nombre == "sniffer_wifi" and not CONFIG["wifi_monitor_iface"]:
        return {"Fuente": _FUENTES[nombre], "Estado": "No configurado", "Detalle": "Interfaz monitor no configurada", "Eventos": 0}
    if nombre == "ti_updater" and not CONFIG["ti_habilitado"]:
        return {"Fuente": _FUENTES[nombre], "Estado": "No configurado", "Detalle": "SENTINEL_TI_ENABLED=false", "Eventos": 0}

    error = info.get("error")
    if error:
        return {"Fuente": _FUENTES[nombre], "Estado": "Error", "Detalle": str(error), "Eventos": info.get("procesados", 0)}
    if not info.get("activo"):
        return {"Fuente": _FUENTES[nombre], "Estado": "Detenido", "Detalle": "El hilo no está activo", "Eventos": info.get("procesados", 0)}

    ultimo = info.get("ultimo_evento")
    if nombre == "ti_updater":
        ultimo = info.get("ultima_actualizacion") or ultimo
    detalle = _edad_texto(ahora - ultimo) if ultimo else "esperando primer evento"
    estado = "Operativo"
    # Falta de tráfico puede ser normal; se comunica como atención, no como caída.
    if ultimo and ahora - ultimo > 3600 and nombre in {"sniffer_tls", "sniffer_lan", "suricata_tail", "zeek_watch"}:
        estado = "Sin actividad"
    return {"Fuente": _FUENTES[nombre], "Estado": estado, "Detalle": detalle, "Eventos": info.get("procesados", 0)}


def resumen() -> dict:
    """Snapshot serializable para UI, API futura y pruebas sin captura real."""
    ahora = time.time()
    fuentes = [_estado_fuente(nombre, state.estado_hilos.get(nombre, {}), ahora) for nombre in _FUENTES]
    estados = [f["Estado"] for f in fuentes if f["Estado"] != "No configurado"]
    if "Error" in estados or "Detenido" in estados:
        estado_global = "Crítico"
    elif "Sin actividad" in estados:
        estado_global = "Atención"
    else:
        estado_global = "Operativo"

    buffers = [
        ("Flujos TLS", state.flujos_tls), ("Eventos LAN", state.eventos_lan),
        ("Alertas IDS", state.alertas_ids), ("Eventos Zeek", state.eventos_zeek),
        ("Incidentes", state.incidentes),
    ]
    capacidad = [{"Buffer": nombre, "Eventos": len(buffer), "Capacidad": buffer.maxlen,
                  "Uso (%)": round((len(buffer) / buffer.maxlen) * 100, 1)} for nombre, buffer in buffers]
    db_path = CONFIG["db_path"]
    db_bytes = sum(os.path.getsize(ruta) for ruta in (db_path, f"{db_path}-wal", f"{db_path}-shm") if os.path.exists(ruta))
    return {
        "estado_global": estado_global,
        "fuentes": fuentes,
        "capacidad": capacidad,
        "db_path": db_path,
        "db_mb": round(db_bytes / (1024 * 1024), 2),
        "db_limite_mb": CONFIG["db_max_tamano_mb"],
        "uptime_seg": max(0, ahora - min((v.get("iniciado_en", ahora) for v in state.estado_hilos.values()), default=ahora)),
    }
