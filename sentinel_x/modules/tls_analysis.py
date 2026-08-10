"""
Análisis de tráfico TLS: extracción de SNI, cálculo de JA3 completo,
cruce contra base de hashes conocidos, y detección heurística de DGA
(Domain Generation Algorithms) vía entropía de Shannon.
"""

import hashlib
import math

from core.config import CONFIG
from core.logger import get_logger

logger = get_logger("tls_analysis")

_GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}

# Base local de hashes JA3 documentados públicamente (proyecto salesforce/ja3
# y reportes de threat intel). Pequeña muestra representativa: clientes
# legítimos comunes + algunas familias de malware conocidas por su JA3 fijo.
JA3_CONOCIDOS: dict[str, str] = {
    "e7d705a3286e19ea42f587b344ee6865": "Tor Browser (típico)",
    "51c64c77e60f3980eea90869b68c58a8": "Chrome (Windows, típico)",
    "cd08e31494f9531f560d64c695473da9": "curl/libcurl (default)",
    "a0e9f5d64349fb13191bc781f81f42e1": "Python requests (default)",
    "6734f37431670b3ab4292b8f60f29984": "Trickbot (histórico)",
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (default beacon, histórico)",
    "8f52d1ce303fb4a6515836aec3cc7twq": "Metasploit (histórico, ejemplo ilustrativo)",
}


def filtrar_grease(valores: list) -> list:
    return [v for v in valores if v not in _GREASE_VALUES]


def calcular_ja3(client_hello) -> str:
    """
    JA3 = md5(SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats)
    Filtra GREASE (RFC 8701) y TLS_EMPTY_RENEGOTIATION_INFO (0x00FF).
    """
    try:
        ssl_version = int(client_hello.version) if hasattr(client_hello, "version") else 0

        ciphers_raw = list(client_hello.ciphers) if hasattr(client_hello, "ciphers") else []
        ciphers = filtrar_grease([c for c in ciphers_raw if c != 0x00FF])

        ext_types, curvas, formatos_punto = [], [], []
        if hasattr(client_hello, "ext") and client_hello.ext:
            for ext in client_hello.ext:
                tipo = getattr(ext, "type", None)
                if tipo is None or tipo in _GREASE_VALUES:
                    continue
                ext_types.append(tipo)
                if tipo == 10:
                    grupos = getattr(ext, "groups", None) or getattr(ext, "named_curves", [])
                    curvas = filtrar_grease(list(grupos))
                elif tipo == 11:
                    formatos_punto = list(getattr(ext, "ecpl", None) or getattr(ext, "formats", []))

        ja3_string = ",".join([
            str(ssl_version),
            "-".join(str(c) for c in ciphers),
            "-".join(str(e) for e in ext_types),
            "-".join(str(c) for c in curvas),
            "-".join(str(p) for p in formatos_punto),
        ])
        return hashlib.md5(ja3_string.encode()).hexdigest()
    except Exception as exc:
        logger.debug("Error calculando JA3: %s", exc)
        return "error-ja3"


def identificar_ja3(ja3_hash: str) -> str | None:
    """Devuelve la descripción conocida de un hash JA3, o None."""
    return JA3_CONOCIDOS.get(ja3_hash)


def extraer_sni(client_hello) -> str:
    """Extrae el SNI (extensión tipo 0) de un ClientHello."""
    if not (hasattr(client_hello, "ext") and client_hello.ext):
        return "Cifrado/Desconocido"
    for ext in client_hello.ext:
        if getattr(ext, "type", None) == 0:
            try:
                return ext.servernames[0].servername.decode("utf-8")
            except (UnicodeDecodeError, IndexError, AttributeError):
                return "Error-SNI-decodificación"
    return "Cifrado/Desconocido"


def entropia_shannon(texto: str) -> float:
    """Calcula la entropía de Shannon de un string (bits/símbolo)."""
    if not texto:
        return 0.0
    longitud = len(texto)
    frecuencias = {c: texto.count(c) for c in set(texto)}
    return -sum(
        (f / longitud) * math.log2(f / longitud) for f in frecuencias.values()
    )


def es_posible_dga(sni: str) -> dict | None:
    """
    Heurística simple de DGA: alta entropía en el subdominio + TLD sospechoso.
    No es un clasificador ML, es una señal barata para priorizar revisión manual.
    """
    if not sni or sni in ("Cifrado/Desconocido", "Error-SNI-decodificación"):
        return None

    partes = sni.split(".")
    if len(partes) < 2:
        return None

    subdominio = partes[0]
    tld = partes[-1].lower()
    entropia = entropia_shannon(subdominio)

    es_tld_sospechoso = tld in CONFIG["dga_tlds_sospechosos"]
    es_entropia_alta = entropia > CONFIG["dga_umbral_entropia"] and len(subdominio) >= 8

    if es_entropia_alta or (es_tld_sospechoso and entropia > 3.0):
        return {
            "sni": sni,
            "entropia": round(entropia, 2),
            "tld_sospechoso": es_tld_sospechoso,
            "razon": (
                "Entropía alta en subdominio" if es_entropia_alta
                else "TLD sospechoso + entropía moderada"
            ),
        }
    return None
