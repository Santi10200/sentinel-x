"""
Identificación de dispositivos más allá del prefijo MAC.

El OUI de una MAC dice quién fabricó la tarjeta de red (MediaTek,
Espressif, Realtek...), no qué aparato es. Y los celulares modernos usan
MAC aleatoria por red (iOS 14+, Android 10+), así que su OUI no significa
nada. Lo que sí identifica un dispositivo es lo que él mismo anuncia:

  DHCP (67/68)   hostname (opción 12), clase de fabricante (opción 60) y
                 lista de parámetros (opción 55, huella del sistema).
  mDNS (5353)    Bonjour/Chromecast/impresoras: modelo exacto en TXT
                 (model=iPhone15,2, md=Chromecast, ty=HP LaserJet...).
  SSDP (1900)    UPnP: XML con fabricante y modelo (Smart TV, routers).

Cada fuente produce una "observación" que se guarda en SQLite
(identidad_obs). Al mostrar el inventario, `resolver()` combina las
observaciones de cada equipo con la etiqueta manual del usuario y decide
nombre, tipo, modelo y sistema con un nivel de confianza explícito.

Las funciones de interpretación son puras (bytes/texto -> dict) para
poder probarlas sin red; la captura y las consultas activas están al
final del módulo.
"""

import ipaddress
import json
import re
import socket
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

from core import database
from core.logger import get_logger

logger = get_logger("identidad")

ALTA, MEDIA, BAJA, MANUAL = "Alta", "Media", "Baja", "Manual"


# ── MAC ──────────────────────────────────────────────────────────────────

def normalizar_mac(mac: str | None) -> str:
    return (mac or "").strip().lower().replace("-", ":")


def es_mac_aleatoria(mac: str | None) -> bool:
    """
    Bit "localmente administrada" del primer octeto (segundo carácter 2, 6,
    A o E). Lo usan iOS/Android/Windows para la MAC privada por red; un
    fabricante nunca asigna MACs con ese bit.
    """
    mac = normalizar_mac(mac)
    try:
        primer_octeto = int(mac[:2], 16)
    except ValueError:
        return False
    return bool(primer_octeto & 0x02) and not primer_octeto & 0x01


# ── Apple ────────────────────────────────────────────────────────────────

# Identificador interno -> nombre comercial. Solo los que se pueden afirmar
# con certeza; el resto se muestra como "iPhone (iPhone18,3)".
APPLE_MODELOS = {
    "iPhone10,1": "iPhone 8", "iPhone10,4": "iPhone 8", "iPhone10,2": "iPhone 8 Plus",
    "iPhone10,5": "iPhone 8 Plus", "iPhone10,3": "iPhone X", "iPhone10,6": "iPhone X",
    "iPhone11,2": "iPhone XS", "iPhone11,4": "iPhone XS Max", "iPhone11,6": "iPhone XS Max",
    "iPhone11,8": "iPhone XR", "iPhone12,1": "iPhone 11", "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max", "iPhone12,8": "iPhone SE (2.ª gen.)",
    "iPhone13,1": "iPhone 12 mini", "iPhone13,2": "iPhone 12", "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max", "iPhone14,4": "iPhone 13 mini", "iPhone14,5": "iPhone 13",
    "iPhone14,2": "iPhone 13 Pro", "iPhone14,3": "iPhone 13 Pro Max",
    "iPhone14,6": "iPhone SE (3.ª gen.)", "iPhone14,7": "iPhone 14", "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro", "iPhone15,3": "iPhone 14 Pro Max", "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus", "iPhone16,1": "iPhone 15 Pro", "iPhone16,2": "iPhone 15 Pro Max",
    "iPhone17,3": "iPhone 16", "iPhone17,4": "iPhone 16 Plus", "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max", "iPhone17,5": "iPhone 16e",
}

# Prefijo del identificador -> (familia, tipo de dispositivo, sistema)
_APPLE_FAMILIAS = [
    ("iPhone", "iPhone", "Smartphone", "iOS"),
    ("iPad", "iPad", "Tablet", "iPadOS"),
    ("iPod", "iPod touch", "Reproductor multimedia", "iOS"),
    ("MacBookPro", "MacBook Pro", "PC / portátil", "macOS"),
    ("MacBookAir", "MacBook Air", "PC / portátil", "macOS"),
    ("MacBook", "MacBook", "PC / portátil", "macOS"),
    ("Macmini", "Mac mini", "PC / portátil", "macOS"),
    ("MacPro", "Mac Pro", "PC / portátil", "macOS"),
    ("iMac", "iMac", "PC / portátil", "macOS"),
    ("Mac", "Mac", "PC / portátil", "macOS"),
    ("AppleTV", "Apple TV", "Smart TV / streaming", "tvOS"),
    ("AudioAccessory", "HomePod", "Altavoz inteligente", "audioOS"),
    ("Watch", "Apple Watch", "Reloj inteligente", "watchOS"),
]


def modelo_apple(identificador: str) -> dict | None:
    """'iPhone15,2' -> {modelo: 'iPhone 14 Pro', tipo: 'Smartphone', sistema: 'iOS', fabricante: 'Apple'}"""
    identificador = (identificador or "").strip()
    for prefijo, familia, tipo, sistema in _APPLE_FAMILIAS:
        if re.fullmatch(rf"{prefijo}\d+,\d+", identificador):
            modelo = APPLE_MODELOS.get(identificador, f"{familia} ({identificador})")
            return {"modelo": modelo, "tipo": tipo, "sistema": sistema, "fabricante": "Apple"}
    return None


# ── Hostname ─────────────────────────────────────────────────────────────

# (patrón sobre el hostname en minúsculas, tipo, fabricante, el hostname contiene el modelo)
_PATRONES_HOSTNAME: list[tuple[str, str, str, bool]] = [
    (r"^galaxy[-_ ]?tab", "Tablet", "Samsung", True),
    (r"^(galaxy[-_ ]|sm-[a-z]\d{3})", "Smartphone", "Samsung", True),
    (r"^(redmi|poco[-_ ]|xiaomi|mi[-_ ]?\d)", "Smartphone", "Xiaomi", True),
    (r"^(huawei|honor)[-_ ]", "Smartphone", "Huawei / Honor", True),
    (r"^(oppo|realme|vivo|oneplus)[-_ ]", "Smartphone", "BBK (OPPO / realme / vivo / OnePlus)", True),
    (r"^(moto[-_ ]|motorola)", "Smartphone", "Motorola", True),
    (r"^pixel[-_ ]", "Smartphone", "Google", True),
    (r"^nokia[-_ ]", "Smartphone", "Nokia", True),
    (r"iphone", "Smartphone", "Apple", False),
    (r"ipad", "Tablet", "Apple", False),
    (r"macbook", "PC / portátil", "Apple", False),
    (r"(imac|mac-?mini|mac-?studio)", "PC / portátil", "Apple", False),
    (r"apple-?watch", "Reloj inteligente", "Apple", False),
    (r"^android[-_][0-9a-f]{6,}", "Smartphone / tablet", "Android (fabricante no anunciado)", False),
    (r"^(desktop|laptop)-[a-z0-9]{7}$", "PC / portátil", "", False),
    (r"(chromecast|google-?home|nest-?(mini|hub|audio))", "Smart TV / streaming", "Google", False),
    (r"(lgwebostv|webos)", "Smart TV / streaming", "LG", False),
    (r"(samsung.*tv|tizen)", "Smart TV / streaming", "Samsung", False),
    (r"(bravia|sony.*tv)", "Smart TV / streaming", "Sony", False),
    (r"(roku|fire-?tv|firestick|aft[a-z]{2,})", "Smart TV / streaming", "", False),
    (r"(echo|alexa|amazon-[0-9a-f]+)", "Altavoz inteligente", "Amazon", False),
    (r"(playstation|^ps[345]|xbox|nintendo|switch)", "Consola", "", False),
    (r"^(hp[0-9a-f]{6}|npi[0-9a-f]{6})", "Impresora", "HP", False),
    (r"^(brn|brw)[0-9a-f]{6,}", "Impresora", "Brother", False),
    (r"^(epson|et-\d)", "Impresora", "Epson", False),
    (r"^canon", "Impresora", "Canon", False),
    (r"^(esp[-_]|espressif|tasmota|shelly|sonoff|tuya|wiz[-_]|ewelink|tapo|kasa)", "IoT / domótica", "", False),
    (r"(camera|cam[-_]|ipc[-_]|hikvision|dahua|ezviz|imou)", "Cámara IP", "", False),
    (r"(router|gateway|openwrt|fritz|mikrotik|tplink|tp-link|archer)", "Router / red", "", False),
    (r"(synology|diskstation|qnap|nas)", "NAS", "", False),
]


def humanizar(texto: str) -> str:
    return re.sub(r"[-_]+", " ", texto).strip()


def clasificar_hostname(hostname: str | None) -> dict | None:
    """Tipo/fabricante/modelo deducidos del nombre que anuncia el equipo."""
    nombre = (hostname or "").strip().removesuffix(".local").removesuffix(".lan")
    if not nombre:
        return None
    bajo = nombre.lower()
    for patron, tipo, fabricante, contiene_modelo in _PATRONES_HOSTNAME:
        if re.search(patron, bajo):
            return {
                "tipo": tipo, "fabricante": fabricante,
                "modelo": humanizar(nombre) if contiene_modelo else "",
                "sistema": "Windows" if bajo.startswith(("desktop-", "laptop-")) else "",
            }
    return None


# ── DHCP ─────────────────────────────────────────────────────────────────

def clasificar_dhcp(vendor_class: str, param_req: list[int]) -> dict:
    """Sistema operativo a partir de la opción 60 y la huella de la opción 55."""
    vc = (vendor_class or "").strip()
    m = re.match(r"android-dhcp-(\d+)", vc, re.I)
    if m:
        return {"sistema": f"Android {m.group(1)}", "tipo": "Smartphone / tablet"}
    if vc.upper().startswith("MSFT"):
        return {"sistema": "Windows", "tipo": "PC / portátil"}
    if vc.lower().startswith("dhcpcd"):
        return {"sistema": "Linux / Android (dhcpcd)", "tipo": ""}
    if vc.lower().startswith("udhcp"):
        return {"sistema": "Linux embebido", "tipo": "IoT / equipo embebido"}
    params = set(param_req or [])
    # Apple no envía opción 60; pide 108 (solo IPv6) y 114 (portal cautivo) desde iOS 16 / macOS 13.
    if not vc and {108, 114} <= params:
        return {"sistema": "iOS / macOS", "tipo": ""}
    # Windows 10/11 piden 249 (rutas estáticas Microsoft) y 252 (WPAD).
    if not vc and {249, 252} <= params:
        return {"sistema": "Windows", "tipo": "PC / portátil"}
    return {"sistema": "", "tipo": ""}


def _texto(valor) -> str:
    if isinstance(valor, bytes):
        return valor.decode("utf-8", errors="replace").strip("\x00 ")
    return str(valor or "").strip()


def parsear_dhcp(pkt) -> dict | None:
    """Petición DHCP de un cliente (scapy) -> observación, o None."""
    from scapy.layers.dhcp import BOOTP, DHCP
    if not (pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)) or pkt[BOOTP].op != 1:
        return None
    opciones = {}
    for opcion in pkt[DHCP].options:
        if isinstance(opcion, tuple) and len(opcion) >= 2:
            opciones[opcion[0]] = opcion[1]
    mac = normalizar_mac(bytes(pkt[BOOTP].chaddr)[:6].hex(":"))
    hostname = _texto(opciones.get("hostname"))
    vendor_class = _texto(opciones.get("vendor_class_id"))
    params = list(opciones.get("param_req_list") or [])
    if not (hostname or vendor_class or params):
        return None
    ip = _texto(opciones.get("requested_addr")) or (pkt[BOOTP].ciaddr if pkt[BOOTP].ciaddr != "0.0.0.0" else "")

    datos = {"hostname": hostname, "vendor_class": vendor_class,
             "huella_dhcp": ",".join(str(p) for p in params)}
    datos.update({k: v for k, v in clasificar_dhcp(vendor_class, params).items() if v})
    por_nombre = clasificar_hostname(hostname)
    if por_nombre:
        datos.update({k: v for k, v in por_nombre.items() if v and not datos.get(k)})
    return {"clave": mac, "mac": mac, "ip": str(ip), "fuente": "DHCP", "datos": datos}


# ── mDNS ─────────────────────────────────────────────────────────────────

def _txt(rdata) -> dict[str, str]:
    pares = {}
    for entrada in rdata if isinstance(rdata, list) else [rdata]:
        texto = _texto(entrada)
        if "=" in texto:
            clave, valor = texto.split("=", 1)
            pares[clave.strip().lower()] = valor.strip()
    return pares


def _registros(dns) -> list:
    registros = []
    for campo in ("an", "ns", "ar"):
        valor = getattr(dns, campo, None)
        if valor is None:
            continue
        if isinstance(valor, list):  # scapy >= 2.5
            registros.extend(valor)
        else:  # scapy antiguo: registros encadenados
            while valor is not None and hasattr(valor, "rrname"):
                registros.append(valor)
                valor = valor.payload if hasattr(valor.payload, "rrname") else None
    return registros


def parsear_mdns(dns, ip_origen: str) -> dict | None:
    """Respuesta mDNS (capa DNS de scapy) -> observación por IP, o None."""
    datos: dict[str, str] = {}
    servicios = set()
    for rr in _registros(dns):
        nombre = _texto(rr.rrname).rstrip(".")
        bajo = nombre.lower()
        if rr.type == 1 and bajo.endswith(".local") and "._" not in bajo:  # A
            datos.setdefault("hostname", nombre.removesuffix(".local"))
        if rr.type != 16:  # solo TXT a partir de aquí
            continue
        txt = _txt(rr.rdata)
        instancia = nombre.split("._", 1)[0]
        servicio = "_" + nombre.split("._", 1)[1] if "._" in nombre else ""
        servicios.add(servicio.split(".local")[0])

        for clave in ("model", "rpmd", "am"):  # _device-info, _companion-link, _airplay/_raop
            apple = modelo_apple(txt.get(clave, ""))
            if apple:
                datos.update(apple)
        if "_googlecast" in servicio:
            datos.update({"modelo": txt.get("md", "Chromecast"), "tipo": "Smart TV / streaming",
                          "fabricante": datos.get("fabricante") or "Google (Cast)"})
            if txt.get("fn"):
                datos["nombre"] = txt["fn"]
        if any(s in servicio for s in ("_ipp", "_printer", "_pdl-datastream")):
            modelo = txt.get("ty") or txt.get("usb_mdl", "")
            datos.update({"tipo": "Impresora", "modelo": modelo or datos.get("modelo", ""),
                          "fabricante": txt.get("usb_mfg", datos.get("fabricante", ""))})
        if "_hap" in servicio and txt.get("md"):  # HomeKit
            datos.setdefault("modelo", txt["md"])
            datos.setdefault("tipo", "IoT / domótica")
        if instancia and not instancia.startswith("_"):
            datos.setdefault("nombre", instancia)

    if not datos:
        return None
    if servicios:
        datos["servicios"] = ", ".join(sorted(s for s in servicios if s))
    return {"clave": f"ip:{ip_origen}", "mac": "", "ip": ip_origen, "fuente": "mDNS", "datos": datos}


# ── SSDP / UPnP ──────────────────────────────────────────────────────────

def parsear_ssdp(texto: str) -> dict:
    """Cabeceras de un NOTIFY o respuesta a M-SEARCH -> {location, server, st}."""
    cabeceras = {}
    for linea in texto.splitlines()[1:]:
        if ":" in linea:
            k, v = linea.split(":", 1)
            cabeceras[k.strip().lower()] = v.strip()
    return {"location": cabeceras.get("location", ""), "server": cabeceras.get("server", ""),
            "st": cabeceras.get("st") or cabeceras.get("nt", "")}


_TIPO_UPNP = [
    ("mediarenderer", "Smart TV / streaming"), ("tv", "Smart TV / streaming"),
    ("internetgatewaydevice", "Router / red"), ("wlanaccesspoint", "Router / red"),
    ("printer", "Impresora"), ("mediaserver", "NAS / servidor multimedia"),
    ("camera", "Cámara IP"), ("speaker", "Altavoz inteligente"),
]


def parsear_descripcion_upnp(xml_texto: str) -> dict:
    """XML de descripción UPnP -> {nombre, fabricante, modelo, tipo}."""
    raiz = ET.fromstring(xml_texto)
    dispositivo = next((e for e in raiz.iter() if e.tag.split("}")[-1] == "device"), None)
    if dispositivo is None:
        return {}
    campos = {}
    for hijo in dispositivo:
        etiqueta = hijo.tag.split("}")[-1]
        if etiqueta in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType"):
            campos[etiqueta] = (hijo.text or "").strip()
    modelo = campos.get("modelName", "")
    numero = campos.get("modelNumber", "")
    if numero and numero not in modelo:  # "Samsung TV" + "QN55Q60" -> "Samsung TV QN55Q60"
        modelo = f"{modelo} {numero}"
    tipo_upnp = campos.get("deviceType", "").lower()
    tipo = next((t for clave, t in _TIPO_UPNP if clave in tipo_upnp), "")
    return {k: v for k, v in {
        "nombre": campos.get("friendlyName", ""), "fabricante": campos.get("manufacturer", ""),
        "modelo": modelo.strip(), "tipo": tipo,
    }.items() if v}


def _es_ip_privada(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


def obtener_descripcion_upnp(location: str, ip_origen: str, timeout: float = 2.0) -> dict:
    """
    Descarga el XML UPnP. Solo si la URL apunta a la misma IP privada que
    respondió (un LOCATION no puede hacernos pedir URLs de otros equipos ni
    de Internet) y con un tope de 64 KB.
    """
    partes = urllib.parse.urlparse(location)
    if partes.scheme != "http" or partes.hostname != ip_origen or not _es_ip_privada(ip_origen):
        return {}
    try:
        with urllib.request.urlopen(location, timeout=timeout) as resp:
            return parsear_descripcion_upnp(resp.read(65536).decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.debug("UPnP %s: %s", location, exc)
        return {}


# ── Persistencia de observaciones y etiquetas ────────────────────────────

_lock_cache = threading.Lock()
_cache_obs: dict[tuple[str, str], dict] = {}


def registrar(obs: dict | None) -> None:
    """Fusiona la observación con la anterior de la misma fuente y la guarda si cambió."""
    if not obs or not obs.get("clave"):
        return
    llave = (obs["clave"], obs["fuente"])
    with _lock_cache:
        previo = _cache_obs.get(llave)
        if previo is None:
            filas = database.consultar(
                "SELECT datos FROM identidad_obs WHERE clave = ? AND fuente = ?", llave)
            previo = json.loads(filas[0]["datos"]) if filas else {}
        datos = {**previo, **{k: v for k, v in obs["datos"].items() if v}}
        if datos == previo and llave in _cache_obs:
            return
        _cache_obs[llave] = datos
    database.ejecutar("""
        INSERT INTO identidad_obs (clave, fuente, mac, ip, datos, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(clave, fuente) DO UPDATE SET
            mac=COALESCE(NULLIF(excluded.mac, ''), identidad_obs.mac),
            ip=COALESCE(NULLIF(excluded.ip, ''), identidad_obs.ip),
            datos=excluded.datos, timestamp=excluded.timestamp
    """, (obs["clave"], obs["fuente"], obs.get("mac", ""), obs.get("ip", ""),
          json.dumps(datos, ensure_ascii=False), time.time()))


def observaciones() -> list[dict]:
    filas = database.consultar("SELECT * FROM identidad_obs")
    for f in filas:
        f["datos"] = json.loads(f["datos"] or "{}")
    return filas


def guardar_etiqueta(mac: str, etiqueta: str, tipo: str = "", notas: str = "") -> None:
    mac = normalizar_mac(mac)
    if not etiqueta.strip() and not tipo.strip():
        database.ejecutar("DELETE FROM etiquetas_dispositivo WHERE mac = ?", (mac,))
        return
    database.ejecutar("""
        INSERT INTO etiquetas_dispositivo (mac, etiqueta, tipo, notas, actualizado)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(mac) DO UPDATE SET etiqueta=excluded.etiqueta, tipo=excluded.tipo,
            notas=excluded.notas, actualizado=excluded.actualizado
    """, (mac, etiqueta.strip(), tipo.strip(), notas.strip(), time.time()))


def etiquetas() -> dict[str, dict]:
    return {f["mac"]: f for f in database.consultar("SELECT * FROM etiquetas_dispositivo")}


# ── Fusión de evidencias ─────────────────────────────────────────────────

_PRIORIDAD_FUENTE = {"mDNS": 3, "SSDP": 3, "DHCP": 2}


def resolver(host: dict, obs: list[dict], etiqueta: dict | None = None) -> dict:
    """
    Identidad final de un equipo del inventario. Orden de confianza:
    etiqueta manual > modelo anunciado por mDNS/SSDP (Alta) > hostname o
    sistema por DHCP (Media) > MAC privada o fabricante del chip (Baja).
    """
    mac = normalizar_mac(host.get("mac"))
    ip = host.get("ip", "")
    propias = [o for o in obs if (mac and o["clave"] == mac) or o["clave"] == f"ip:{ip}"
               or (mac and normalizar_mac(o.get("mac")) == mac)]
    # El hostname del inventario (DNS inverso o leases DHCP) también es evidencia:
    # los routers con dnsmasq registran en DNS el nombre que anuncia cada equipo.
    por_nombre = clasificar_hostname(host.get("hostname"))
    if por_nombre and not any(o["fuente"] == "DHCP" for o in propias):
        propias.append({"clave": mac, "fuente": host.get("fuente_hostname") or "Hostname",
                        "datos": {**{k: v for k, v in por_nombre.items() if v},
                                  "hostname": host["hostname"]}})
    propias.sort(key=lambda o: -_PRIORIDAD_FUENTE.get(o["fuente"], 1))

    def primero(campo: str) -> tuple[str, str]:
        for o in propias:
            if o["datos"].get(campo):
                return o["datos"][campo], o["fuente"]
        return "", ""

    modelo, fuente_modelo = primero("modelo")
    tipo, fuente_tipo = primero("tipo")
    sistema, _ = primero("sistema")
    fabricante, _ = primero("fabricante")
    nombre, _ = primero("nombre")
    hostname, _ = primero("hostname")
    privada = es_mac_aleatoria(mac)

    if fuente_modelo in ("mDNS", "SSDP"):
        confianza = ALTA
    elif modelo or tipo or sistema:
        confianza = MEDIA
    else:
        confianza = BAJA

    if not tipo and sistema == "iOS / macOS":
        tipo = "Dispositivo Apple"
    if not tipo:
        # Último recurso. La marca NO se rellena con el fabricante del chip (OUI):
        # ese dato va aparte como "chip de red".
        tipo = "Smartphone / tablet (MAC privada)" if privada else (host.get("tipo") or "Desconocido")
    fuentes = sorted({o["fuente"] for o in propias})

    if etiqueta:
        nombre = etiqueta.get("etiqueta") or nombre
        if etiqueta.get("tipo"):
            tipo = etiqueta["tipo"]
        confianza = MANUAL
        fuentes = ["Manual"] + fuentes

    return {
        "nombre": nombre or hostname or host.get("hostname") or "",
        "dispositivo": tipo or "Desconocido",
        "modelo": modelo,
        "marca": fabricante,
        "sistema": sistema or (host.get("os_detectado") if host.get("os_detectado") not in (None, "N/A") else ""),
        "confianza": confianza,
        "fuente_identidad": ", ".join(fuentes) or ("MAC privada" if privada else "OUI"),
        "mac_privada": privada,
    }


def resolver_inventario(inventario: list[dict]) -> list[dict]:
    obs = observaciones()
    etiq = etiquetas()
    return [{**host, **resolver(host, obs, etiq.get(normalizar_mac(host.get("mac"))))} for host in inventario]


# ── Captura pasiva y descubrimiento activo ───────────────────────────────

_pool_upnp = ThreadPoolExecutor(max_workers=4, thread_name_prefix="upnp")
_upnp_consultados: dict[str, float] = {}


def _programar_upnp(location: str, ip: str) -> None:
    """Descarga el XML UPnP en segundo plano, como mucho una vez por hora y URL."""
    with _lock_cache:
        if time.time() - _upnp_consultados.get(location, 0) < 3600:
            return
        _upnp_consultados[location] = time.time()

    def _tarea():
        datos = obtener_descripcion_upnp(location, ip)
        if datos:
            registrar({"clave": f"ip:{ip}", "mac": "", "ip": ip, "fuente": "SSDP", "datos": datos})
    _pool_upnp.submit(_tarea)


def procesar_paquete(pkt) -> bool:
    """Callback del sniffer de identidad. Devuelve True si produjo una observación."""
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dns import DNS
    if not pkt.haslayer(UDP):
        return False
    puertos = {pkt[UDP].sport, pkt[UDP].dport}
    if puertos & {67, 68}:
        obs = parsear_dhcp(pkt)
        registrar(obs)
        return obs is not None
    if not pkt.haslayer(IP):
        return False
    ip = pkt[IP].src
    if 5353 in puertos and pkt.haslayer(DNS) and pkt[DNS].qr == 1:
        obs = parsear_mdns(pkt[DNS], ip)
        registrar(obs)
        return obs is not None
    if 1900 in puertos:
        cabeceras = parsear_ssdp(bytes(pkt[UDP].payload).decode("utf-8", errors="replace"))
        if cabeceras["location"]:
            _programar_upnp(cabeceras["location"], ip)
            return True
    return False


SERVICIOS_MDNS = [
    "_device-info._tcp.local", "_companion-link._tcp.local", "_airplay._tcp.local",
    "_raop._tcp.local", "_googlecast._tcp.local", "_ipp._tcp.local", "_printer._tcp.local",
    "_pdl-datastream._tcp.local", "_hap._tcp.local", "_spotify-connect._tcp.local",
]


def descubrir_mdns(ip_local: str | None, timeout: float = 3.0) -> int:
    """Pregunta por servicios Bonjour pidiendo respuesta unicast (bit QU). Devuelve nº de observaciones."""
    from scapy.layers.dns import DNS, DNSQR
    consulta = bytes(DNS(rd=0, qd=[DNSQR(qname=s, qtype="PTR", qclass=0x8001) for s in SERVICIOS_MDNS]))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    n = 0
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        if ip_local:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip_local))
        sock.settimeout(0.5)
        sock.sendto(consulta, ("224.0.0.251", 5353))
        limite = time.time() + timeout
        while time.time() < limite:
            try:
                datos, (ip, _) = sock.recvfrom(9000)
            except socket.timeout:
                continue
            try:
                obs = parsear_mdns(DNS(datos), ip)
            except Exception:
                continue
            if obs:
                registrar(obs)
                n += 1
    finally:
        sock.close()
    return n


def descubrir_ssdp(ip_local: str | None, timeout: float = 3.0) -> int:
    """M-SEARCH ssdp:all y descarga de la descripción UPnP de cada equipo que responde."""
    mensaje = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
               "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    ubicaciones: dict[str, str] = {}
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if ip_local:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip_local))
        sock.settimeout(0.5)
        sock.sendto(mensaje, ("239.255.255.250", 1900))
        limite = time.time() + timeout
        while time.time() < limite:
            try:
                datos, (ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            location = parsear_ssdp(datos.decode("utf-8", errors="replace"))["location"]
            if location and ip not in ubicaciones:
                ubicaciones[ip] = location
    finally:
        sock.close()

    n = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        for ip, datos in zip(ubicaciones, pool.map(lambda kv: obtener_descripcion_upnp(kv[1], kv[0]),
                                                    ubicaciones.items())):
            if datos:
                registrar({"clave": f"ip:{ip}", "mac": "", "ip": ip, "fuente": "SSDP", "datos": datos})
                n += 1
    return n


def descubrir_activo(ip_local: str | None, timeout: float = 3.0) -> dict[str, int]:
    """mDNS y SSDP en paralelo. Nunca lanza: un fallo de red deja el escaneo ARP intacto."""
    resultado = {"mDNS": 0, "SSDP": 0}

    def _seguro(nombre, funcion):
        try:
            resultado[nombre] = funcion(ip_local, timeout)
        except OSError as exc:
            logger.warning("Descubrimiento %s falló: %s", nombre, exc)

    hilos = [threading.Thread(target=_seguro, args=("mDNS", descubrir_mdns)),
             threading.Thread(target=_seguro, args=("SSDP", descubrir_ssdp))]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()
    return resultado
