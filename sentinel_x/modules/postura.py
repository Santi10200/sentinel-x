"""
Evaluación de postura de seguridad (exposición), no de ataques en curso.

Los detectores (beaconing, lateral, ML, IDS) responden "¿alguien nos está
atacando?". Este módulo responde "¿qué tan expuesta está la red?", que es
lo que NIST CSF 2.0 pide en IDENTIFY (ID.RA-01: vulnerabilidades
identificadas) y PROTECT (PR.DS-02: datos en tránsito protegidos,
PR.PS-01: configuración segura, PR.IR-01: red protegida de acceso no
autorizado).

Tres fuentes, todas ya capturadas por Sentinel-X:
  1. Inventario (Nmap)   -> servicios inseguros publicados en cada host.
  2. Eventos LAN         -> protocolos en texto claro realmente usados.
  3. Redes Wi-Fi         -> cifrado débil o sin protección de tramas (PMF).

Cada hallazgo incluye severidad, subcategoría NIST, técnica MITRE que
facilita y una recomendación concreta, para que un estudiante o una pyme
sepa qué hacer sin tener que investigar cada caso.
"""

import re

import pandas as pd

_ORDEN_SEVERIDAD = {"Crítica": 0, "Alta": 1, "Media": 2, "Baja": 3}

# puerto -> (servicio, severidad, MITRE, recomendación)
SERVICIOS_INSEGUROS: dict[int, tuple[str, str, str, str]] = {
    23: ("Telnet", "Crítica", "T1021 / T1040",
         "Deshabilitar Telnet y usar SSH con autenticación por clave."),
    2323: ("Telnet alternativo (IoT)", "Crítica", "T1021 / T1040",
           "Puerto típico de botnets IoT (Mirai). Deshabilitar y actualizar firmware."),
    512: ("rexec", "Crítica", "T1021", "Eliminar servicios r* y usar SSH."),
    513: ("rlogin", "Crítica", "T1021", "Eliminar servicios r* y usar SSH."),
    514: ("rsh", "Crítica", "T1021", "Eliminar servicios r* y usar SSH."),
    21: ("FTP", "Alta", "T1040 / T1105",
         "Reemplazar por SFTP/FTPS; FTP envía credenciales en claro."),
    69: ("TFTP", "Media", "T1105", "Restringir TFTP a la VLAN de gestión o deshabilitarlo."),
    110: ("POP3", "Media", "T1040", "Forzar POP3S (995) o desactivar POP3 sin TLS."),
    143: ("IMAP", "Media", "T1040", "Forzar IMAPS (993) o desactivar IMAP sin TLS."),
    161: ("SNMP", "Media", "T1046 / T1040",
          "Usar SNMPv3 con autenticación y cifrado; cambiar comunidades por defecto."),
    445: ("SMB", "Media", "T1021.002",
          "Limitar SMB a servidores de archivos, deshabilitar SMBv1 y exigir firma SMB."),
    139: ("NetBIOS", "Media", "T1021.002", "Deshabilitar NetBIOS sobre TCP/IP si no se usa."),
    3389: ("RDP", "Media", "T1021.001",
           "Exigir NLA, MFA y limitar RDP a una VPN o host bastión."),
    5900: ("VNC", "Alta", "T1021.005",
           "VNC suele ir sin cifrar: túnel SSH/VPN y contraseña robusta, o deshabilitar."),
    5985: ("WinRM HTTP", "Media", "T1021.006", "Usar WinRM sobre HTTPS (5986) y restringir orígenes."),
    1433: ("MSSQL", "Media", "T1190", "No exponer la base de datos fuera de la capa de aplicación."),
    3306: ("MySQL", "Media", "T1190", "Ligar MySQL a localhost o a la red de aplicación."),
    5432: ("PostgreSQL", "Media", "T1190", "Restringir pg_hba.conf a los orígenes necesarios."),
    6379: ("Redis", "Alta", "T1190", "Redis sin autenticación permite RCE: activar ACL/requirepass y bind local."),
    9200: ("Elasticsearch", "Alta", "T1190", "Activar seguridad (TLS + usuarios) y no exponer 9200."),
    27017: ("MongoDB", "Alta", "T1190", "Activar autenticación y bind a interfaces internas."),
    1900: ("UPnP/SSDP", "Media", "T1190", "Deshabilitar UPnP en el router."),
    80: ("HTTP (administración sin TLS)", "Baja", "T1040",
         "Si es un panel de administración, habilitar HTTPS y desactivar HTTP."),
}

# Protocolos que, vistos en el tráfico, implican datos/credenciales en claro.
PROTOCOLOS_EN_CLARO: dict[int, tuple[str, str]] = {
    21: ("FTP", "Alta"), 23: ("Telnet", "Crítica"), 110: ("POP3", "Alta"),
    143: ("IMAP", "Alta"), 389: ("LDAP sin TLS", "Alta"), 161: ("SNMP v1/v2c", "Media"),
    1883: ("MQTT sin TLS", "Media"), 80: ("HTTP", "Baja"), 25: ("SMTP sin TLS", "Baja"),
}

# Cifrado Wi-Fi (valor de wifi_security) -> (severidad, recomendación)
_WIFI_RIESGO: dict[str, tuple[str, str]] = {
    "WEP (vulnerable)": ("Crítica", "WEP se rompe en minutos: migrar a WPA3 o, como mínimo, WPA2-AES."),
    "Abierta": ("Alta", "Red sin cifrar: usar WPA3/WPA2 o, para redes públicas, OWE (Enhanced Open)."),
    "WPA (legacy)": ("Alta", "WPA/TKIP está obsoleto: migrar a WPA2-AES o WPA3."),
    "RSN malformado": ("Media", "Elemento RSN inválido: revisar firmware del AP (posible AP falso)."),
}


def _hallazgo(categoria, activo, detalle, severidad, nist, mitre, recomendacion) -> dict:
    return {
        "Categoría": categoria, "Activo": activo, "Detalle": detalle,
        "Severidad": severidad, "NIST CSF": nist, "MITRE": mitre,
        "Recomendación": recomendacion,
    }


def _puertos_de_texto(texto: str | None) -> list[int]:
    """'22/tcp, 80/tcp' -> [22, 80]"""
    if not texto:
        return []
    return [int(p) for p in re.findall(r"(\d+)/(?:tcp|udp)", texto)]


def servicios_inseguros(inventario: list[dict]) -> list[dict]:
    """Servicios peligrosos publicados por cada host (requiere escaneo Nmap)."""
    hallazgos = []
    for host in inventario or []:
        ip = host.get("ip") or host.get("IP")
        for puerto in _puertos_de_texto(host.get("puertos_abiertos")):
            if puerto not in SERVICIOS_INSEGUROS:
                continue
            servicio, severidad, mitre, recomendacion = SERVICIOS_INSEGUROS[puerto]
            hallazgos.append(_hallazgo(
                "Servicio inseguro expuesto", ip,
                f"{servicio} abierto en {puerto}/tcp ({host.get('tipo') or 'tipo desconocido'})",
                severidad, "ID.RA-01 · PR.PS-01", mitre, recomendacion,
            ))
    return hallazgos


def protocolos_en_claro(eventos_lan: list[dict], min_eventos: int = 1) -> list[dict]:
    """Uso real de protocolos sin cifrado observado en la red (PR.DS-02)."""
    if not eventos_lan:
        return []
    df = pd.DataFrame(eventos_lan)
    if df.empty or not {"Origen", "Destino", "Puerto"}.issubset(df.columns):
        return []
    df = df[df["Puerto"].isin(PROTOCOLOS_EN_CLARO.keys())]
    if "Inicio" in df.columns:
        df = df[df["Inicio"].fillna(True).astype(bool)]
    if df.empty:
        return []

    hallazgos = []
    for (origen, destino, puerto), grupo in df.groupby(["Origen", "Destino", "Puerto"]):
        if len(grupo) < min_eventos:
            continue
        nombre, severidad = PROTOCOLOS_EN_CLARO[int(puerto)]
        hallazgos.append(_hallazgo(
            "Protocolo en texto claro", origen,
            f"{nombre} hacia {destino}:{puerto} ({len(grupo)} conexiones)",
            severidad, "PR.DS-02", "T1040",
            f"Sustituir {nombre} por su variante cifrada (TLS/SSH) o aislarlo en una VLAN de gestión.",
        ))
    return hallazgos


def wifi_debil(redes: list[dict]) -> list[dict]:
    """Redes Wi-Fi con cifrado débil o sin PMF (802.11w)."""
    hallazgos = []
    for red in redes or []:
        cifrado = red.get("cifrado", "")
        cipher_suites = red.get("cipher_suites") or []
        if isinstance(cipher_suites, str):
            cipher_suites = [c.strip() for c in cipher_suites.split(",")]
        activo = f"{red.get('ssid', '?')} ({red.get('bssid', '?')})"

        if cifrado in _WIFI_RIESGO:
            severidad, recomendacion = _WIFI_RIESGO[cifrado]
            hallazgos.append(_hallazgo(
                "Wi-Fi con cifrado débil", activo, cifrado,
                severidad, "PR.DS-02 · PR.IR-01", "T1040 / T1557", recomendacion,
            ))
            continue
        if "TKIP" in cipher_suites:
            hallazgos.append(_hallazgo(
                "Wi-Fi con cifrado débil", activo, f"{cifrado} anuncia TKIP",
                "Media", "PR.DS-02", "T1040", "Desactivar TKIP y dejar solo CCMP (AES).",
            ))
        if cifrado in ("WPA2-Personal", "WPA2/WPA3 transición") and red.get("pmf") != "Requerido":
            hallazgos.append(_hallazgo(
                "Wi-Fi sin PMF obligatorio", activo,
                f"{cifrado}, PMF {str(red.get('pmf', 'desconocido')).lower()}",
                "Baja", "PR.IR-01", "T1499 (deauth)",
                "Activar PMF/802.11w obligatorio (o WPA3, que lo exige) contra ataques de desautenticación.",
            ))
    return hallazgos


def evaluar(inventario: list[dict], eventos_lan: list[dict], redes_wifi: list[dict]) -> pd.DataFrame:
    """Todos los hallazgos de postura ordenados por severidad."""
    hallazgos = (
        servicios_inseguros(inventario)
        + protocolos_en_claro(eventos_lan)
        + wifi_debil(redes_wifi)
    )
    if not hallazgos:
        return pd.DataFrame()
    df = pd.DataFrame(hallazgos)
    df["_orden"] = df["Severidad"].map(_ORDEN_SEVERIDAD)
    return df.sort_values(["_orden", "Activo"]).drop(columns="_orden").reset_index(drop=True)
