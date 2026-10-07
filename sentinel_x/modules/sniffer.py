"""
Captura de paquetes con Scapy.

Dos sniffers independientes, cada uno en su propio hilo daemon:
  1. sniffer_tls: puerto 443/8443 TCP + 443 UDP (QUIC) -> análisis TLS/JA3.
  2. sniffer_lan: tráfico dentro de la red local, sin importar puerto,
     usado por el módulo de movimiento lateral (no hace análisis TLS,
     solo registra metadatos: IP origen, IP destino, puerto, tamaño).

Ambos usan store=0 para no acumular paquetes en RAM (Scapy los descarta
después del callback). Todo error queda reflejado en core.state.estado_hilos
para que la UI lo muestre sin tener que adivinar por qué dejó de llegar tráfico.
"""

import time

from scapy.all import sniff
from scapy.sessions import TCPSession
from scapy.layers.tls.all import TLS, TLSClientHello
from scapy.layers.inet import IP, TCP, UDP

from core.config import CONFIG
from core.logger import get_logger
from core import state, database
from core.network_iface import interfaz_configurada
from modules import tls_analysis
from modules import wifi_security, identidad

logger = get_logger("sniffer")


def _callback_tls(pkt) -> None:
    if not (pkt.haslayer(TLS) and pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return

    ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
    puerto_dst = pkt[TCP].dport

    sni, ja3_hash = "Cifrado/Desconocido", "N/A"

    if pkt.haslayer(TLSClientHello):
        ch = pkt[TLSClientHello]
        sni = tls_analysis.extraer_sni(ch)
        ja3_hash = tls_analysis.calcular_ja3(ch)

    flujo = {
        "Origen": ip_src, "Destino": ip_dst, "Puerto": puerto_dst,
        "SNI": sni, "JA3": ja3_hash,
        "Timestamp": time.time(), "Tamaño (bytes)": len(pkt),
    }
    with state.lock_flujos_tls:
        state.flujos_tls.append(flujo)
        state.registrar_evento("sniffer_tls")

    # Persistir solo ClientHello: evita una escritura SQLite por cada segmento TLS.
    if pkt.haslayer(TLSClientHello):
        database.insertar("flujos_tls", {
            "timestamp": flujo["Timestamp"], "origen": ip_src, "destino": ip_dst,
            "puerto": puerto_dst, "sni": sni, "ja3": ja3_hash,
            "ja3_conocido": tls_analysis.identificar_ja3(ja3_hash) or "",
            "tamano_bytes": len(pkt),
        })


def es_inicio_udp(puerto_src: int, puerto_dst: int) -> bool:
    """
    UDP no tiene handshake: se asume que habla el cliente cuando sale de un
    puerto efímero hacia uno de servicio. Una respuesta (servicio -> efímero)
    no cuenta, así un servidor DNS/DHCP no parece "escanear" a sus clientes.
    """
    return not (puerto_src < 1024 and puerto_dst >= 1024)


def _callback_lan(pkt) -> None:
    if not (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
        return

    ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        puerto_src, puerto_dst, proto = tcp.sport, tcp.dport, "TCP"
        # SYN sin ACK = intento de conexión nuevo; el resto son datos o respuestas.
        inicio = bool(tcp.flags & 0x02) and not bool(tcp.flags & 0x10)
    else:
        puerto_src, puerto_dst, proto = pkt[UDP].sport, pkt[UDP].dport, "UDP"
        inicio = es_inicio_udp(puerto_src, puerto_dst)

    with state.lock_eventos_lan:
        state.eventos_lan.append({
            "Origen": ip_src, "Destino": ip_dst,
            "Puerto origen": puerto_src, "Puerto": puerto_dst, "Proto": proto,
            "Inicio": inicio,
            "Timestamp": time.time(), "Tamaño (bytes)": len(pkt),
        })
        state.registrar_evento("sniffer_lan")


def iniciar_sniffer_tls() -> None:
    iface = interfaz_configurada()
    state.estado_hilos["sniffer_tls"]["activo"] = True
    state.estado_hilos["sniffer_tls"]["error"] = None
    logger.info("Sniffer TLS iniciado en '%s'.", iface)
    try:
        sniff(
            iface=iface,
            filter="tcp port 443 or tcp port 8443",
            prn=_callback_tls,
            store=0,
            session=TCPSession,
        )
    except PermissionError:
        msg = "Sin permisos. Ejecuta con sudo o CAP_NET_RAW."
        logger.error(msg)
        state.estado_hilos["sniffer_tls"]["error"] = msg
    except Exception as exc:
        logger.error("Error en sniffer TLS: %s", exc)
        state.estado_hilos["sniffer_tls"]["error"] = str(exc)
    finally:
        state.estado_hilos["sniffer_tls"]["activo"] = False


def iniciar_sniffer_lan(cidr: str | None = None) -> None:
    """
    cidr: si se especifica, solo captura tráfico dentro de esa red
    (recomendado para no saturar el buffer con tráfico de internet).
    """
    iface = interfaz_configurada()
    # Evita duplicar en el análisis LAN los flujos que procesa el sniffer TLS.
    excluye_tls = "not (tcp port 443 or tcp port 8443 or udp port 443)"
    filtro = f"net {cidr} and {excluye_tls}" if cidr else excluye_tls

    state.estado_hilos["sniffer_lan"]["activo"] = True
    state.estado_hilos["sniffer_lan"]["error"] = None
    logger.info("Sniffer LAN iniciado en '%s' (filtro: %s).", iface, filtro)
    try:
        sniff(iface=iface, filter=filtro, prn=_callback_lan, store=0)
    except PermissionError:
        msg = "Sin permisos. Ejecuta con sudo o CAP_NET_RAW."
        logger.error(msg)
        state.estado_hilos["sniffer_lan"]["error"] = msg
    except Exception as exc:
        logger.error("Error en sniffer LAN: %s", exc)
        state.estado_hilos["sniffer_lan"]["error"] = str(exc)
    finally:
        state.estado_hilos["sniffer_lan"]["activo"] = False


def _callback_wifi(pkt) -> None:
    red = wifi_security.analizar_trama_wifi(pkt)
    if not red:
        return
    with state.lock_redes_wifi:
        state.redes_wifi[red["bssid"]] = red
        state.registrar_evento("sniffer_wifi")
    database.upsert_red_wifi(red)


def iniciar_sniffer_wifi() -> None:
    """Captura pasiva de beacons/probe responses en una interfaz monitor configurada."""
    iface = CONFIG["wifi_monitor_iface"]
    if not iface:
        return
    state.estado_hilos["sniffer_wifi"]["activo"] = True
    state.estado_hilos["sniffer_wifi"]["error"] = None
    logger.info("Sniffer Wi-Fi pasivo iniciado en '%s'.", iface)
    try:
        sniff(iface=iface, filter="type mgt subtype beacon or type mgt subtype probe-resp",
              prn=_callback_wifi, store=0)
    except PermissionError:
        msg = "Sin permisos para captura Wi-Fi. Usa CAP_NET_RAW/CAP_NET_ADMIN."
        logger.error(msg)
        state.estado_hilos["sniffer_wifi"]["error"] = msg
    except Exception as exc:
        logger.error("Error en sniffer Wi-Fi: %s", exc)
        state.estado_hilos["sniffer_wifi"]["error"] = str(exc)
    finally:
        state.estado_hilos["sniffer_wifi"]["activo"] = False


def _callback_identidad(pkt) -> None:
    try:
        if identidad.procesar_paquete(pkt):
            state.registrar_evento("sniffer_identidad")
    except Exception as exc:  # un paquete malformado no debe tumbar la captura
        logger.debug("Paquete de identidad no interpretable: %s", exc)


def iniciar_sniffer_identidad() -> None:
    """
    Escucha pasiva de DHCP, mDNS y SSDP: lo que los dispositivos anuncian
    de sí mismos (hostname, modelo, sistema). Va aparte del sniffer LAN
    porque las peticiones DHCP salen de 0.0.0.0 hacia 255.255.255.255 y
    no entran en su filtro "net <cidr>".
    """
    iface = interfaz_configurada()
    state.estado_hilos["sniffer_identidad"]["activo"] = True
    state.estado_hilos["sniffer_identidad"]["error"] = None
    logger.info("Sniffer de identidad (DHCP/mDNS/SSDP) iniciado en '%s'.", iface)
    try:
        sniff(iface=iface, filter="udp and (port 67 or port 68 or port 5353 or port 1900)",
              prn=_callback_identidad, store=0)
    except PermissionError:
        msg = "Sin permisos. Ejecuta con sudo o CAP_NET_RAW."
        logger.error(msg)
        state.estado_hilos["sniffer_identidad"]["error"] = msg
    except Exception as exc:
        logger.error("Error en sniffer de identidad: %s", exc)
        state.estado_hilos["sniffer_identidad"]["error"] = str(exc)
    finally:
        state.estado_hilos["sniffer_identidad"]["activo"] = False
