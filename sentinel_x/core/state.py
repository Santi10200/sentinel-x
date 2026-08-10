"""
Estado global compartido entre todos los hilos de Sentinel-X.

REGLA DE ORO: ningún Lock vive dentro de st.session_state. Streamlit
re-ejecuta el script en cada interacción del usuario; si el lock viviera
en session_state, cada recarga podría crear una instancia nueva mientras
los hilos de fondo siguen referenciando la instancia vieja -> deadlock o
corrupción silenciosa. Por eso todo vive aquí, a nivel de módulo, y se
importa una sola vez (Python cachea los módulos importados).
"""

import collections
import threading

from core.config import CONFIG

# ── Locks dedicados por buffer ───────────────────────────────────────────
# Un lock por buffer (en vez de uno global) reduce contención: el sniffer
# TLS no se bloquea esperando a que el lector de Suricata termine.
lock_flujos_tls = threading.Lock()
lock_eventos_lan = threading.Lock()
lock_alertas = threading.Lock()
lock_zeek = threading.Lock()
lock_incidentes = threading.Lock()
lock_inventario = threading.Lock()
lock_ti_cache = threading.Lock()
lock_redes_wifi = threading.Lock()

# ── Buffers circulares ───────────────────────────────────────────────────
flujos_tls: collections.deque = collections.deque(maxlen=CONFIG["buffer_max_flujos_tls"])
eventos_lan: collections.deque = collections.deque(maxlen=CONFIG["buffer_max_eventos_lan"])
alertas_ids: collections.deque = collections.deque(maxlen=CONFIG["buffer_max_alertas"])
eventos_zeek: collections.deque = collections.deque(maxlen=CONFIG["buffer_max_zeek"])
incidentes: collections.deque = collections.deque(maxlen=CONFIG["buffer_max_incidentes"])

# Inventario de red: dict mutable {ip: perfil}, no deque (clave = IP)
inventario_red: dict = {}
# Redes observadas pasivamente: {bssid: datos de seguridad 802.11}.
redes_wifi: dict = {}

# Cache de Threat Intelligence: {indicador: {"malicioso": bool, "fuente": str, "ts": float}}
ti_cache: dict = {}

# ── Estados de los distintos hilos en background ────────────────────────
estado_hilos: dict = {
    "sniffer_tls": {"activo": False, "error": None, "procesados": 0},
    "sniffer_lan": {"activo": False, "error": None, "procesados": 0},
    "suricata_tail": {"activo": False, "error": None, "procesados": 0},
    "zeek_watch": {"activo": False, "error": None, "procesados": 0},
    "ti_updater": {"activo": False, "error": None, "ultima_actualizacion": None},
    "sniffer_wifi": {"activo": False, "error": None, "procesados": 0},
}


def snapshot(buffer: collections.deque, lock: threading.Lock) -> list:
    """Copia thread-safe de cualquier buffer circular."""
    with lock:
        return list(buffer)


def snapshot_dict(d: dict, lock: threading.Lock) -> dict:
    """Copia thread-safe de cualquier dict compartido."""
    with lock:
        return dict(d)
