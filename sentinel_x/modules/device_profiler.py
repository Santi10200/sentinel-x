"""
Descubrimiento y perfilado de dispositivos en la red local.

Combina 5 fuentes en orden de costo creciente:
  1. ARP scan (Scapy)              -> IP + MAC                [~1s total]
  2. OUI local + heurística nombre -> Fabricante + Tipo        [~0s/host]
  3. DHCP leases                   -> Hostname declarado       [~0s, una lectura]
  4. DNS reverso                   -> Hostname resuelto        [~0.1-1s/host]
  5. Nmap -O -sV (opcional)        -> SO + puertos + servicios [~5-30s/host]

Las 4 primeras siempre se ejecutan; Nmap es opt-in porque es lento.
El enriquecimiento por host se paraleliza con ThreadPoolExecutor.
"""

import concurrent.futures
import ipaddress
import os
import re
import socket
import subprocess
import urllib.request
import json
import xml.etree.ElementTree as ET

from scapy.all import ARP, Ether, srp

from core.config import CONFIG
from core.logger import get_logger
from core.network_iface import interfaz_configurada, ip_y_mascara
from modules import identidad

logger = get_logger("device_profiler")

# ── OUI: prefijos MAC conocidos -> (fabricante, tipo) ────────────────────
OUI_DB_LOCAL: dict[str, tuple[str, str]] = {
    "00:50:56": ("VMware", "Máquina virtual"), "00:0C:29": ("VMware", "Máquina virtual"),
    "00:15:5D": ("Microsoft Hyper-V", "Máquina virtual"), "08:00:27": ("VirtualBox", "Máquina virtual"),
    "52:54:00": ("QEMU/KVM", "Máquina virtual"),
    "B8:27:EB": ("Raspberry Pi", "SBC/IoT"), "DC:A6:32": ("Raspberry Pi", "SBC/IoT"),
    "E4:5F:01": ("Raspberry Pi", "SBC/IoT"),
    "54:60:09": ("Google", "Chromecast/Smart TV"), "3C:5A:B4": ("Google", "Chromecast/Smart TV"),
    "00:17:88": ("Philips Hue", "IoT/Domótica"), "EC:B5:FA": ("Philips Hue", "IoT/Domótica"),
    "18:B4:30": ("Nest Labs", "IoT/Termostato"),
    "64:16:66": ("Amazon", "Echo/Alexa"), "FC:65:DE": ("Amazon", "Echo/Alexa"),
    "44:65:0D": ("Amazon", "Fire TV"), "F0:F0:02": ("Amazon", "Kindle"),
    "00:17:F2": ("Apple", "Mac/iPhone/iPad"), "00:1B:63": ("Apple", "Mac/iPhone/iPad"),
    "A4:C3:F0": ("Apple", "Mac/iPhone/iPad"), "3C:22:FB": ("Apple", "Mac/iPhone/iPad"),
    "00:1D:60": ("Cisco", "Switch/Router"), "00:13:C4": ("Cisco", "Switch/Router"),
    "00:0F:90": ("Fortinet", "Firewall/UTM"),
    "00:1A:8C": ("Ubiquiti", "AP/Router"), "24:A4:3C": ("Ubiquiti", "AP/Router"),
    "00:14:BF": ("Linksys", "Router doméstico"), "1C:7E:E5": ("D-Link", "Router doméstico"),
    "C8:D3:A3": ("TP-Link", "Router doméstico"), "50:C7:BF": ("TP-Link", "Router doméstico"),
    "8C:8D:28": ("Intel", "PC/Laptop"), "D8:CB:8A": ("Dell", "PC/Servidor"),
    "B0:83:FE": ("Samsung", "Smartphone/TV"), "8C:77:12": ("Samsung", "Smartphone/TV"),
    "00:19:C1": ("Nintendo", "Consola"), "00:22:AA": ("Microsoft Xbox", "Consola"),
    "00:0A:E4": ("Siemens", "PLC/Industrial"),
    "00:11:32": ("Synology", "NAS"), "00:08:9B": ("QNAP", "NAS"),
}

_VENDOR_TIPO_HEURISTICA: list[tuple[str, str]] = [
    (r"camera|cam|hikvision|dahua|axis|vivotek", "Cámara IP"),
    (r"printer|print|epson|canon|brother|lexmark|zebra", "Impresora"),
    (r"nas|synology|qnap|western digital|wd|seagate", "NAS/Almacenamiento"),
    (r"router|gateway|mikrotik|zyxel|netgear|tenda", "Switch/Router"),
    (r"ap|access point|ubiquiti|aruba|ruckus|meraki", "Punto de acceso WiFi"),
    (r"firewall|checkpoint|palo alto|fortinet|sophos", "Firewall/Seguridad"),
    (r"raspberry|arduino|esp32|esp8266", "SBC/IoT"),
    (r"amazon|echo|ring|blink", "Dispositivo Amazon"),
    (r"apple", "Apple (Mac/iPhone/iPad)"), (r"samsung", "Samsung (Smartphone/TV)"),
    (r"cisco|juniper|extreme", "Equipo de red empresarial"),
    (r"vmware|virtualbox|hyper.v|qemu|xen", "Máquina virtual"),
    (r"intel|realtek|broadcom|atheros", "PC/Laptop"),
    (r"dell|hp|lenovo|acer|asus|msi", "PC/Servidor"),
    (r"xbox|playstation|nintendo|valve", "Consola de juegos"),
    (r"google|nest|chromecast", "Dispositivo Google"),
    (r"android|xiaomi|huawei|motorola|oneplus", "Smartphone Android"),
    (r"siemens|schneider|rockwell|omron", "PLC/Industrial"),
    (r"tv|television|lg|sony|vizio|hisense|roku", "Smart TV/Media Player"),
]


def _arp_scan(ip_rango: str) -> list[dict]:
    arp = ARP(pdst=ip_rango)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    resultado = srp(ether / arp, timeout=2, verbose=0, iface=interfaz_configurada())[0]
    return [{"IP": r.psrc, "MAC": r.hwsrc} for _, r in resultado]


_oui_sistema: dict[str, str] | None = None


def parsear_oui(texto: str) -> dict[str, str]:
    """
    Formatos de Wireshark ("00:00:0C<TAB>Cisco<TAB>Cisco Systems, Inc") y de
    nmap ("00000C Cisco Systems") -> {"00:00:0C": "Cisco Systems, Inc"}.
    Se ignoran los bloques más pequeños (/28, /36) de Wireshark.
    """
    tabla = {}
    for linea in texto.splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        partes = re.split(r"\s+", linea, maxsplit=1) if "\t" not in linea else linea.split("\t")
        prefijo = partes[0].upper().replace("-", ":")
        if "/" in prefijo or len(partes) < 2:
            continue
        if re.fullmatch(r"[0-9A-F]{6}", prefijo):
            prefijo = ":".join(prefijo[i:i + 2] for i in range(0, 6, 2))
        if re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){2}", prefijo):
            nombre = (partes[2] if len(partes) > 2 and partes[2].strip() else partes[1]).strip()
            tabla.setdefault(prefijo, nombre)
    return tabla


def _oui_de_sistema(mac: str) -> str:
    global _oui_sistema
    if _oui_sistema is None:
        _oui_sistema = {}
        for ruta in CONFIG["rutas_oui_sistema"]:
            try:
                with open(ruta, encoding="utf-8", errors="replace") as f:
                    for k, v in parsear_oui(f.read()).items():
                        _oui_sistema.setdefault(k, v)
            except OSError:
                continue
        logger.info("Base OUI del sistema: %d prefijos.", len(_oui_sistema))
    return _oui_sistema.get(mac.upper()[:8], "")


def _oui_local(mac: str) -> tuple[str, str]:
    return OUI_DB_LOCAL.get(mac.upper()[:8], ("", ""))


def _oui_online(mac: str) -> str:
    try:
        oui = mac.replace(":", "").replace("-", "").upper()[:6]
        req = urllib.request.Request(
            f"https://www.macvendorlookup.com/api/v2/{oui}",
            headers={"User-Agent": "Sentinel-X/2.0"},
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode())
            entrada = data[0] if isinstance(data, list) and data else data
            return entrada.get("company", "") if isinstance(entrada, dict) else ""
    except Exception:
        return ""


def _inferir_tipo(vendor: str) -> str:
    vendor_l = vendor.lower()
    for patron, tipo in _VENDOR_TIPO_HEURISTICA:
        if re.search(patron, vendor_l):
            return tipo
    return "Desconocido"


def _dns_reverso(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def leer_dhcp_leases() -> dict[str, str]:
    """{mac_lower: hostname} desde dnsmasq o isc-dhcp-server."""
    leases: dict[str, str] = {}
    for ruta in CONFIG["rutas_dhcp_leases"]:
        if not os.path.exists(ruta):
            continue
        try:
            contenido = open(ruta).read()
            for linea in contenido.splitlines():
                partes = linea.strip().split()
                if len(partes) >= 4 and partes[3] != "*":
                    leases[partes[1].lower()] = partes[3]
            for bloque in re.findall(r"lease\s+[\d.]+\s*\{([^}]+)\}", contenido, re.S):
                mac_m = re.search(r"hardware ethernet\s+([\da-f:]+)", bloque, re.I)
                hn_m = re.search(r'client-hostname\s+"([^"]+)"', bloque, re.I)
                if mac_m and hn_m:
                    leases[mac_m.group(1).lower()] = hn_m.group(1)
        except OSError:
            continue
        if leases:
            break
    return leases


def parsear_nmap_xml(xml_texto: str) -> dict:
    """
    Interpreta la salida `-oX -` de Nmap. A diferencia del texto, el XML
    trae producto, versión y CPE de cada servicio, que es lo que necesita
    la búsqueda de CVE en el NVD (modules/vulnerabilidades.py).
    """
    resultado = {"os_detectado": "N/A", "puertos_abiertos": "", "servicios": "", "servicios_detalle": "[]"}
    raiz = ET.fromstring(xml_texto)
    host = raiz.find("host")
    if host is None:
        return resultado

    osmatch = host.find("os/osmatch")
    if osmatch is not None and osmatch.get("name"):
        resultado["os_detectado"] = osmatch.get("name")[:60]

    puertos, servicios, detalle = [], [], []
    for puerto in host.findall("ports/port"):
        estado = puerto.find("state")
        if estado is None or estado.get("state") != "open":
            continue
        proto, numero = puerto.get("protocol", "tcp"), int(puerto.get("portid", 0))
        svc = puerto.find("service")
        nombre = svc.get("name", "") if svc is not None else ""
        producto = svc.get("product", "") if svc is not None else ""
        version = svc.get("version", "") if svc is not None else ""
        cpes = [c.text.strip() for c in svc.findall("cpe") if c.text] if svc is not None else []

        puertos.append(f"{numero}/{proto}")
        servicios.append(" ".join(x for x in (nombre, producto, version) if x))
        detalle.append({"puerto": numero, "proto": proto, "servicio": nombre,
                        "producto": producto, "version": version, "cpes": cpes})

    resultado["puertos_abiertos"] = ", ".join(puertos)
    resultado["servicios"] = ", ".join(servicios[:12])
    resultado["servicios_detalle"] = json.dumps(detalle, ensure_ascii=False)
    return resultado


def perfil_nmap(ip: str) -> dict:
    """nmap -O -sV con salida XML. Requiere root y nmap instalado. Timeout configurable."""
    resultado = {"os_detectado": "N/A", "puertos_abiertos": "", "servicios": "", "servicios_detalle": "[]"}
    try:
        proc = subprocess.run(
            ["nmap", "-O", "-sV", "--version-intensity", str(CONFIG["nmap_version_intensity"]),
             "-T4", "--open", "-oX", "-", ip],
            capture_output=True, text=True, timeout=CONFIG["nmap_timeout_seg"],
        )
        resultado = parsear_nmap_xml(proc.stdout)
    except FileNotFoundError:
        resultado["os_detectado"] = "nmap no instalado"
    except subprocess.TimeoutExpired:
        resultado["os_detectado"] = "Timeout"
    except ET.ParseError as exc:
        logger.warning("Salida XML de Nmap inválida para %s: %s", ip, exc)
    except Exception as exc:
        logger.warning("Nmap error en %s: %s", ip, exc)
    return resultado


def escanear_y_perfilar(
    ip_rango: str, usar_nmap: bool = False, usar_ieee: bool = True, usar_descubrimiento: bool = True,
) -> list[dict]:
    try:
        ip_rango = str(ipaddress.ip_network(ip_rango, strict=False))
    except ValueError:
        return [{"Error": "El rango debe ser una red válida en formato CIDR (ej. 192.168.1.0/24)."}]
    try:
        hosts = _arp_scan(ip_rango)
    except PermissionError:
        return [{"Error": "Permisos insuficientes. Ejecuta con sudo o CAP_NET_RAW."}]
    except Exception as exc:
        return [{"Error": f"Fallo en el escaneo ARP: {exc}"}]

    if not hosts:
        return []

    logger.info("ARP encontró %d hosts. Iniciando perfilado...", len(hosts))
    dhcp_map = leer_dhcp_leases()

    # mDNS/SSDP en paralelo con el perfilado: los modelos quedan en identidad_obs.
    descubrimiento = None
    if usar_descubrimiento:
        info_iface = ip_y_mascara(interfaz_configurada())
        descubrimiento = concurrent.futures.ThreadPoolExecutor(max_workers=1).submit(
            identidad.descubrir_activo, info_iface[0] if info_iface else None)

    def _enriquecer(host: dict) -> dict:
        ip, mac = host["IP"], host["MAC"]
        mac_norm = mac.lower()

        if identidad.es_mac_aleatoria(mac):
            # MAC privada: el prefijo es inventado, consultarlo daría un fabricante falso.
            vendor, tipo = "MAC privada (aleatoria)", "Smartphone / tablet (MAC privada)"
        else:
            vendor_local, tipo_local = _oui_local(mac)
            vendor_sistema = "" if vendor_local else _oui_de_sistema(mac)
            vendor_online = _oui_online(mac) if (usar_ieee and not (vendor_local or vendor_sistema)) else ""
            vendor = vendor_local or vendor_sistema or vendor_online or "Desconocido"
            tipo = tipo_local or _inferir_tipo(vendor)

        hostname_dhcp = dhcp_map.get(mac_norm, "")
        hostname_dns = _dns_reverso(ip) if not hostname_dhcp else ""
        hostname = hostname_dhcp or hostname_dns or ""

        perfil = {
            "ip": ip, "mac": mac, "fabricante": vendor, "tipo": tipo,
            "hostname": hostname,
            "fuente_hostname": "DHCP" if hostname_dhcp else ("DNS reverso" if hostname_dns else "—"),
        }
        if usar_nmap:
            perfil.update(perfil_nmap(ip))
        return perfil

    max_workers = min(len(hosts), 20)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        dispositivos = list(pool.map(_enriquecer, hosts))

    if descubrimiento is not None:
        logger.info("Descubrimiento activo: %s", descubrimiento.result())
    logger.info("Perfilado completado: %d dispositivos.", len(dispositivos))
    return dispositivos
