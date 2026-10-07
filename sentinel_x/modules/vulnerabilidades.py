"""
Búsqueda de vulnerabilidades conocidas (CVE) para los servicios del inventario.

Flujo:
  1. Nmap -sV (modules/device_profiler.py) identifica producto, versión y
     CPE de cada puerto abierto, p. ej. cpe:/a:openbsd:openssh:8.2p1.
  2. El CPE se convierte a formato 2.3 y se consulta la API 2.0 del NVD
     (National Vulnerability Database, NIST) con `cpeName`, que devuelve
     los CVE cuyo rango de versiones afectado incluye esa versión exacta.
  3. Cada CVE se cruza con el catálogo CISA KEV (vulnerabilidades con
     explotación activa conocida, ya descargado por threat_intel): un CVE
     en KEV sube a severidad Crítica sin importar su CVSS.

Corresponde a NIST CSF 2.0 ID.RA-01 (vulnerabilidades identificadas y
registradas) e ID.RA-02 (inteligencia de amenazas externa).

Límites del NVD: 5 peticiones / 30 s sin clave y 50 / 30 s con clave
(gratuita en https://nvd.nist.gov/developers/request-an-api-key, variable
SENTINEL_NVD_API_KEY). Por eso las consultas se hacen bajo demanda, nunca
en el pipeline de análisis, y cada respuesta se cachea en SQLite.

Limitación honesta: la versión que anuncia un banner no siempre refleja
parches retroportados (Debian/Ubuntu parchean OpenSSH sin cambiar la
versión principal). Los resultados son candidatos a verificar, no
vulnerabilidades confirmadas.
"""

import html
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from core import database
from core.config import CONFIG
from core.logger import get_logger
from modules import threat_intel

logger = get_logger("vulnerabilidades")

_lock_peticiones = threading.Lock()
_ultima_peticion = 0.0


# ── CPE ──────────────────────────────────────────────────────────────────

def cpe22_a_23(cpe: str, version: str | None = None, update: str | None = None) -> str | None:
    """
    'cpe:/a:openbsd:openssh:8.2p1' -> 'cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*'.
    Devuelve None si el CPE no trae versión: sin versión, el NVD
    devolvería todos los CVE históricos del producto (inútil y ruidoso).
    """
    if not cpe or not cpe.startswith("cpe:/"):
        return None
    partes = [urllib.parse.unquote(p) for p in cpe[len("cpe:/"):].split(":")]
    if len(partes) < 3 or partes[0] not in ("a", "o", "h"):
        return None
    if version is not None:
        partes = partes[:3] + [version] + ([update] if update else [])
    if len(partes) < 4 or partes[3] in ("", "*", "-"):
        return None
    # En CPE 2.3 los caracteres especiales van escapados con barra invertida.
    partes = [re.sub(r"([^A-Za-z0-9._\-~])", r"\\\1", p) if p not in ("*", "-") else p for p in partes]
    return "cpe:2.3:" + ":".join(partes + ["*"] * (11 - len(partes)))


def candidatos_cpe(cpe22: str) -> list[str]:
    """
    Variantes a probar en orden. Nmap y el diccionario NVD no siempre
    escriben igual la versión: OpenSSH '8.2p1' en Nmap es versión '8.2'
    con update 'p1' en el NVD.
    """
    candidatos = []
    exacto = cpe22_a_23(cpe22)
    if exacto:
        candidatos.append(exacto)
    partes = cpe22[len("cpe:/"):].split(":") if cpe22.startswith("cpe:/") else []
    if len(partes) >= 4:
        m = re.fullmatch(r"(\d+(?:\.\d+)*)([a-z]+\d*)", partes[3])
        if m:
            separado = cpe22_a_23(cpe22, version=m.group(1), update=m.group(2))
            if separado and separado not in candidatos:
                candidatos.append(separado)
    return candidatos


# ── Descripción y aplicabilidad ──────────────────────────────────────────

def limpiar_descripcion(texto: str, limite: int = 900) -> str:
    """
    Las traducciones del NVD traen entidades HTML (&#xa0;) y saltos de línea.
    Se decodifican, se normalizan los espacios y, si hay que recortar, se
    corta en un límite de palabra con "…" en vez de a mitad de palabra.
    """
    texto = re.sub(r"\s+", " ", html.unescape(texto or "")).strip()
    if len(texto) <= limite:
        return texto
    return texto[:limite].rsplit(" ", 1)[0].rstrip(".,;: ") + "…"


# (requisito, patrones en la descripción, aplicabilidad si se cumple).
# Un CVE de dnsmasq que solo afecta con DNSSEC activo no pesa igual que uno
# explotable con la configuración por defecto; el CVSS no distingue eso.
_REQUISITOS: list[tuple[str, tuple[str, ...], str]] = [
    ("Entorno libvirt (virtualización)", ("libvirt",), "Improbable"),
    ("DNSSEC activado", ("dnssec",), "Condicional"),
    ("IPv6 / DHCPv6", ("ipv6", "dhcpv6", "router advertisement", "anuncio de router"), "Condicional"),
    ("TFTP activado", ("tftp",), "Condicional"),
    ("Opciones --add-mac/--add-subnet/--add-cpe-id", ("--add-mac", "--add-subnet", "--add-cpe-id"), "Condicional"),
    ("Modo relay DHCP", ("relay", "retransmisor"), "Condicional"),
]
_ORDEN_APLICABILIDAD = {"Probable": 0, "Condicional": 1, "Improbable": 2}


def evaluar_aplicabilidad(descripcion: str) -> tuple[str, str]:
    """
    ('Probable' | 'Condicional' | 'Improbable', requisitos). Heurística por
    palabras clave de la descripción del NVD: orienta la priorización, pero
    la configuración real del equipo es la que decide.
    """
    texto = (descripcion or "").lower()
    # "compilado sin DNSSEC" / "without IPv6" niegan el requisito, no lo exigen.
    texto = re.sub(r"\b(?:sin|without|no)\s+(?:dnssec|ipv6|dhcpv6|tftp)\b", " ", texto)
    requisitos, aplicabilidad = [], "Probable"
    for etiqueta, patrones, nivel in _REQUISITOS:
        if any(p in texto for p in patrones):
            requisitos.append(etiqueta)
            if _ORDEN_APLICABILIDAD[nivel] > _ORDEN_APLICABILIDAD[aplicabilidad]:
                aplicabilidad = nivel
    return aplicabilidad, ", ".join(requisitos) or "Ninguno (configuración por defecto)"


# ── NVD ──────────────────────────────────────────────────────────────────

def severidad_desde_cvss(cvss: float | None, en_kev: bool = False) -> str:
    if en_kev:
        return "Crítica"
    if cvss is None:
        return "Media"
    if cvss >= 9.0:
        return "Crítica"
    if cvss >= 7.0:
        return "Alta"
    if cvss >= 4.0:
        return "Media"
    return "Baja"


def _cvss(metricas: dict) -> float | None:
    """Puntuación base, priorizando CVSS v4.0 > v3.1 > v3.0 > v2 y la fuente 'Primary' (NVD)."""
    for clave in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lista = metricas.get(clave) or []
        if not lista:
            continue
        lista = sorted(lista, key=lambda m: m.get("type") != "Primary")
        puntuacion = lista[0].get("cvssData", {}).get("baseScore")
        if puntuacion is not None:
            return float(puntuacion)
    return None


def parsear_respuesta_nvd(datos: dict) -> list[dict]:
    """Respuesta JSON de /rest/json/cves/2.0 -> [{cve, cvss, descripcion}]."""
    resultado = []
    for item in datos.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if not cve.get("id") or cve.get("vulnStatus") == "Rejected":
            continue
        descripciones = {d.get("lang"): d.get("value", "") for d in cve.get("descriptions", [])}
        resultado.append({
            "cve": cve["id"],
            "cvss": _cvss(cve.get("metrics", {})),
            "descripcion": limpiar_descripcion(descripciones.get("es") or descripciones.get("en") or ""),
        })
    return resultado


def _esperar_turno() -> None:
    """Respeta la ventana de 30 s del NVD (6 s/petición sin clave, 0,6 s con clave)."""
    global _ultima_peticion
    intervalo = 0.6 if CONFIG["nvd_api_key"] else 6.0
    with _lock_peticiones:
        espera = _ultima_peticion + intervalo - time.time()
        if espera > 0:
            time.sleep(espera)
        _ultima_peticion = time.time()


def _peticion_nvd(cpe23: str) -> dict | None:
    """Una consulta al NVD. None si falla la red; {} si el CPE no existe en el diccionario."""
    params = urllib.parse.urlencode({"cpeName": cpe23, "resultsPerPage": 2000})
    cabeceras = {"User-Agent": "Sentinel-X/2.0"}
    if CONFIG["nvd_api_key"]:
        cabeceras["apiKey"] = CONFIG["nvd_api_key"]
    _esperar_turno()
    try:
        req = urllib.request.Request(f"{CONFIG['nvd_api_url']}?{params}", headers=cabeceras)
        with urllib.request.urlopen(req, timeout=CONFIG["nvd_timeout_seg"]) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        # Un cpeName que no está en el diccionario del NVD no tiene CVE asociados:
        # se trata como respuesta vacía (y se cachea) en vez de como fallo de red.
        if exc.code == 404:
            return {}
        logger.warning("NVD respondió %s para %s", exc.code, cpe23)
        return None
    except Exception as exc:
        logger.warning("Fallo consultando NVD para %s: %s", cpe23, exc)
        return None


def consultar_cpe(cpe23: str, peticion: Callable[[str], dict | None] = _peticion_nvd) -> list[dict] | None:
    """CVE para un CPE 2.3, usando la caché SQLite. None = no se pudo consultar."""
    limite = time.time() - CONFIG["nvd_cache_dias"] * 86400
    cache = database.consultar(
        "SELECT respuesta FROM cve_cache WHERE cpe = ? AND timestamp >= ?", (cpe23, limite)
    )
    if cache:
        return json.loads(cache[0]["respuesta"])

    datos = peticion(cpe23)
    if datos is None:
        return None
    cves = parsear_respuesta_nvd(datos)
    database.ejecutar(
        "INSERT OR REPLACE INTO cve_cache (cpe, timestamp, respuesta) VALUES (?, ?, ?)",
        (cpe23, time.time(), json.dumps(cves, ensure_ascii=False)),
    )
    return cves


# ── Inventario ───────────────────────────────────────────────────────────

def servicios_con_cpe(inventario: list[dict]) -> list[dict]:
    """Aplana el inventario a [{ip, puerto, servicio, cpe22}] para servicios con versión."""
    filas = []
    for host in inventario:
        try:
            detalle = json.loads(host.get("servicios_detalle") or "[]")
        except json.JSONDecodeError:
            continue
        for svc in detalle:
            for cpe in svc.get("cpes", []):
                if cpe22_a_23(cpe):
                    filas.append({
                        "ip": host["ip"], "puerto": svc.get("puerto"),
                        "servicio": " ".join(x for x in (svc.get("producto"), svc.get("version")) if x)
                                    or svc.get("servicio", ""),
                        "cpe22": cpe,
                    })
    return filas


def buscar_vulnerabilidades(
    inventario: list[dict],
    progreso: Callable[[int, int, str], None] | None = None,
    peticion: Callable[[str], dict | None] = _peticion_nvd,
) -> dict:
    """
    Consulta el NVD para cada servicio con CPE versionado y guarda los CVE
    en la tabla `vulnerabilidades` (reemplazando los de cada IP revisada).
    Devuelve un resumen {servicios, consultados, fallidos, cves, kev}.
    """
    servicios = servicios_con_cpe(inventario)
    resumen = {"servicios": len(servicios), "consultados": 0, "fallidos": 0, "cves": 0, "kev": 0}
    filas_por_ip: dict[str, list[tuple]] = {}
    ips_completas: set[str] = {s["ip"] for s in servicios}
    ahora = time.time()

    for i, svc in enumerate(servicios, 1):
        if progreso:
            progreso(i, len(servicios), f"{svc['ip']}:{svc['puerto']} {svc['servicio']}")
        cves, cpe_usado = None, None
        for candidato in candidatos_cpe(svc["cpe22"]):
            respuesta = consultar_cpe(candidato, peticion)
            if respuesta is None:
                continue
            if cves is None or respuesta:
                cves, cpe_usado = respuesta, candidato
            if respuesta:  # sin CVE -> probar la siguiente variante del CPE
                break
        if cves is None:
            resumen["fallidos"] += 1
            ips_completas.discard(svc["ip"])  # no borrar resultados previos de una IP a medias
            continue
        resumen["consultados"] += 1
        for c in cves:
            en_kev = threat_intel.cve_con_explotacion_activa(c["cve"])
            filas_por_ip.setdefault(svc["ip"], []).append((
                ahora, svc["ip"], svc["puerto"], svc["servicio"], cpe_usado, c["cve"], c["cvss"],
                severidad_desde_cvss(c["cvss"], en_kev), int(en_kev), c["descripcion"],
            ))
            resumen["cves"] += 1
            resumen["kev"] += int(en_kev)

    for ip in ips_completas:
        database.ejecutar("DELETE FROM vulnerabilidades WHERE ip = ?", (ip,))
    database.ejecutar_varios("""
        INSERT OR REPLACE INTO vulnerabilidades
            (timestamp, ip, puerto, servicio, cpe, cve, cvss, severidad, kev, descripcion)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, [fila for filas in filas_por_ip.values() for fila in filas])
    logger.info("Búsqueda NVD: %s", resumen)
    return resumen


def vulnerabilidades_guardadas() -> list[dict]:
    """CVE guardados con descripción limpia y aplicabilidad, priorizados."""
    filas = database.consultar("SELECT * FROM vulnerabilidades")
    for f in filas:
        # Limpia también lo guardado por versiones anteriores (entidades HTML, cortes).
        f["descripcion"] = limpiar_descripcion(f.get("descripcion") or "")
        f["aplicabilidad"], f["requisito"] = evaluar_aplicabilidad(f["descripcion"])
    filas.sort(key=lambda f: (_ORDEN_APLICABILIDAD[f["aplicabilidad"]], -(f["kev"] or 0),
                              -(f["cvss"] or 0), f["ip"] or "", f["puerto"] or 0))
    return filas


def hallazgos_postura(filas: list[dict], max_ids: int = 3) -> list[dict]:
    """
    Agrupa por servicio (ip, puerto) para no inundar la postura con cientos
    de CVE de un mismo OpenSSH: un hallazgo por servicio con el peor caso.
    """
    orden = {"Crítica": 0, "Alta": 1, "Media": 2, "Baja": 3}
    grupos: dict[tuple, list[dict]] = {}
    for f in filas:
        grupos.setdefault((f["ip"], f["puerto"]), []).append(f)

    hallazgos = []
    for (ip, puerto), todos in grupos.items():
        for c in todos:
            if "aplicabilidad" not in c:
                c["aplicabilidad"], c["requisito"] = evaluar_aplicabilidad(c.get("descripcion", ""))
        # Los improbables (p. ej. solo con libvirt) no cuentan para la severidad.
        cves = [c for c in todos if c["aplicabilidad"] != "Improbable"]
        if not cves:
            continue
        cves.sort(key=lambda c: (_ORDEN_APLICABILIDAD[c["aplicabilidad"]], -c["kev"], -(c["cvss"] or 0)))
        # Severidad del peor CVE probable; si todos dependen de configuración, la del peor condicional.
        base = [c for c in cves if c["aplicabilidad"] == "Probable"] or cves
        peor = min((c["severidad"] for c in base), key=lambda s: orden.get(s, 9))
        en_kev = [c["cve"] for c in cves if c["kev"]]
        max_cvss = max((c["cvss"] or 0 for c in base), default=0)
        ids = ", ".join(c["cve"] for c in cves[:max_ids])
        conteo = {n: sum(1 for c in todos if c["aplicabilidad"] == n) for n in _ORDEN_APLICABILIDAD}
        detalle = (f"{cves[0]['servicio']} en {puerto}/tcp: {len(todos)} CVE "
                   f"({conteo['Probable']} probables, {conteo['Condicional']} condicionales"
                   + (f", {conteo['Improbable']} improbables" if conteo["Improbable"] else "")
                   + f"; CVSS máx. aplicable {max_cvss:.1f}"
                   + (f", {len(en_kev)} en CISA KEV" if en_kev else "") + f"). Prioridad: {ids}")
        recomendacion = f"Actualizar {cves[0]['servicio']} a una versión corregida"
        recomendacion += (f"; prioridad inmediata por explotación activa ({', '.join(en_kev[:3])})."
                          if en_kev else "; verificar si la distribución ya aplicó el parche (backport).")
        hallazgos.append({
            "Categoría": "Vulnerabilidad conocida (CVE)", "Activo": ip, "Detalle": detalle,
            "Severidad": peor, "NIST CSF": "ID.RA-01" + (" · ID.RA-02" if en_kev else ""),
            "MITRE": "T1210 / T1190", "Recomendación": recomendacion,
        })
    return hallazgos
