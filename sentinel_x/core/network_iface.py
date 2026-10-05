"""Detección y utilidades de interfaz de red."""

import fcntl
import ipaddress
import socket

from core.config import CONFIG
from core.logger import get_logger

logger = get_logger("network_iface")

_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B


def ip_y_mascara(iface: str) -> tuple[str, str] | None:
    """Devuelve (ip, mascara) de una interfaz vía ioctl. None si no tiene IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        iface_b = iface.encode()[:15].ljust(16, b"\x00")
        ip_raw = fcntl.ioctl(s.fileno(), _SIOCGIFADDR, iface_b + b"\x00" * 24)[20:24]
        mask_raw = fcntl.ioctl(s.fileno(), _SIOCGIFNETMASK, iface_b + b"\x00" * 24)[20:24]
        s.close()
        return socket.inet_ntoa(ip_raw), socket.inet_ntoa(mask_raw)
    except OSError:
        return None


def cidr_de_interfaz(iface: str) -> str | None:
    """CIDR de la red a la que pertenece la interfaz. None si no tiene IP."""
    resultado = ip_y_mascara(iface)
    if resultado is None:
        return None
    ip, mask = resultado
    return str(ipaddress.IPv4Network(f"{ip}/{mask}", strict=False))


def listar_interfaces_sistema() -> list[str]:
    """Lee /proc/net/dev para listar todas las interfaces del sistema."""
    try:
        with open("/proc/net/dev") as f:
            lineas = f.readlines()[2:]
        return [l.split(":")[0].strip() for l in lineas if ":" in l]
    except OSError:
        return ["eth0", "eth1", "ens33", "wlan0"]


def detectar_interfaz_activa() -> str:
    """Primera interfaz no excluida que tenga IP asignada. Fallback: eth0."""
    excluidas = CONFIG["interfaces_excluidas"]
    for iface in listar_interfaces_sistema():
        if any(iface.startswith(pref) for pref in excluidas):
            continue
        if ip_y_mascara(iface) is not None:
            logger.info("Interfaz activa detectada: %s", iface)
            return iface
    logger.warning("Sin interfaz activa detectada. Fallback a 'eth0'.")
    return "eth0"


def interfaz_configurada() -> str:
    """Resuelve la interfaz a usar: variable de entorno o autodetección."""
    return CONFIG["interfaz_red"] or detectar_interfaz_activa()
