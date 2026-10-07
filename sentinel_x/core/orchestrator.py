"""
Orquestador de hilos de background.

Streamlit re-ejecuta el script completo en cada interacción del usuario.
Sin un guardián persistente, cada recarga lanzaría sniffers y watchers
nuevos, acumulando hilos zombis que compiten por el mismo socket/archivo.

La solución: un módulo de nivel de proceso (no de sesión) que registra
si los hilos ya fueron lanzados. Como Python cachea los módulos importados,
esta bandera persiste mientras el proceso de Streamlit viva, sin importar
cuántas veces el script se re-ejecute lógicamente.
"""

import threading
import time

from core.logger import get_logger
from core import database, state
from core.config import CONFIG
from modules import sniffer, suricata_reader, zeek_reader, threat_intel, mitre_attack, ml_baseline

logger = get_logger("orchestrator")

_hilos_lanzados = False
_lock_arranque = threading.Lock()


def arrancar_todo(cidr_lan: str | None = None) -> None:
    """
    Lanza todos los hilos daemon necesarios. Idempotente: llamarlo varias
    veces (como hace Streamlit en cada rerun) solo tiene efecto la primera vez.
    """
    global _hilos_lanzados

    with _lock_arranque:
        if _hilos_lanzados:
            return

        logger.info("Arrancando Sentinel-X: inicializando DB...")
        database.inicializar_db()

        # Se marca antes de crear hilos para que un rerun de Streamlit no duplique capturas.
        _hilos_lanzados = True

        hilos = [
            threading.Thread(target=mitre_attack.cargar_indice_mitre, daemon=True, name="mitre-loader"),
            threading.Thread(target=sniffer.iniciar_sniffer_tls, daemon=True, name="sniffer-tls"),
            threading.Thread(
                target=sniffer.iniciar_sniffer_lan, args=(cidr_lan,),
                daemon=True, name="sniffer-lan",
            ),
            threading.Thread(target=suricata_reader.hilo_tail_suricata, daemon=True, name="suricata-tail"),
            threading.Thread(target=zeek_reader.hilo_watch_zeek, daemon=True, name="zeek-watch"),
            threading.Thread(target=ml_baseline.hilo_baseline_ml, daemon=True, name="ml-baseline"),
            threading.Thread(target=sniffer.iniciar_sniffer_identidad, daemon=True, name="sniffer-identidad"),
        ]
        if CONFIG["ti_habilitado"]:
            hilos.append(threading.Thread(
                target=threat_intel.hilo_actualizador_ti, daemon=True, name="ti-updater"
            ))
        else:
            logger.info("Threat Intelligence deshabilitada por SENTINEL_TI_ENABLED.")

        if CONFIG["wifi_monitor_iface"]:
            hilos.append(threading.Thread(
                target=sniffer.iniciar_sniffer_wifi, daemon=True, name="sniffer-wifi"
            ))
        for hilo in hilos:
            # La UI operativa diferencia un sensor recién iniciado de uno detenido.
            estado = state.estado_hilos.get(hilo.name.replace("-", "_"))
            if estado is not None:
                estado["iniciado_en"] = time.time()
            hilo.start()
            logger.info("Hilo '%s' lanzado.", hilo.name)



def ya_arrancado() -> bool:
    return _hilos_lanzados
