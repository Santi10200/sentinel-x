"""
Mapeo de alertas a MITRE ATT&CK.

Suricata incluye en eve.json el campo alert.metadata.mitre_technique_id
cuando las reglas lo definen (común en reglas ET Open y ET Pro recientes).
Este módulo:
  1. Descarga el STIX bundle completo de MITRE una vez (cacheable offline).
  2. Construye un índice técnica_id -> {nombre, táctica, url}.
  3. Expone una función de lookup usada por el motor de correlación y la UI.

Si no hay red disponible, usa un fallback local con las ~25 técnicas más
comunes en detección de red, para que el dashboard nunca se quede sin
contexto mínimo.
"""

import json
import re
import threading
import urllib.request

from core.config import CONFIG
from core.logger import get_logger

logger = get_logger("mitre_attack")

_lock = threading.Lock()
_indice_tecnicas: dict[str, dict] = {}

# Fallback offline: técnicas más relevantes para NDR/IDS de red.
_FALLBACK_TECNICAS = {
    "T1071": {"nombre": "Application Layer Protocol", "tactica": "Command and Control"},
    "T1071.001": {"nombre": "Web Protocols", "tactica": "Command and Control"},
    "T1071.004": {"nombre": "DNS", "tactica": "Command and Control"},
    "T1041": {"nombre": "Exfiltration Over C2 Channel", "tactica": "Exfiltration"},
    "T1046": {"nombre": "Network Service Discovery", "tactica": "Discovery"},
    "T1018": {"nombre": "Remote System Discovery", "tactica": "Discovery"},
    "T1021": {"nombre": "Remote Services", "tactica": "Lateral Movement"},
    "T1021.001": {"nombre": "Remote Desktop Protocol", "tactica": "Lateral Movement"},
    "T1021.002": {"nombre": "SMB/Windows Admin Shares", "tactica": "Lateral Movement"},
    "T1570": {"nombre": "Lateral Tool Transfer", "tactica": "Lateral Movement"},
    "T1190": {"nombre": "Exploit Public-Facing Application", "tactica": "Initial Access"},
    "T1110": {"nombre": "Brute Force", "tactica": "Credential Access"},
    "T1486": {"nombre": "Data Encrypted for Impact", "tactica": "Impact"},
    "T1059": {"nombre": "Command and Scripting Interpreter", "tactica": "Execution"},
    "T1105": {"nombre": "Ingress Tool Transfer", "tactica": "Command and Control"},
    "T1568": {"nombre": "Dynamic Resolution", "tactica": "Command and Control"},
    "T1568.002": {"nombre": "Domain Generation Algorithms", "tactica": "Command and Control"},
    "T1095": {"nombre": "Non-Application Layer Protocol", "tactica": "Command and Control"},
    "T1499": {"nombre": "Endpoint Denial of Service", "tactica": "Impact"},
    "T1595": {"nombre": "Active Scanning", "tactica": "Reconnaissance"},
}


def _construir_indice_desde_stix(bundle: dict) -> dict:
    indice = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        refs = obj.get("external_references", [])
        tid = next((r["external_id"] for r in refs if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        tacticas = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        indice[tid] = {
            "nombre": obj.get("name", tid),
            "tactica": ", ".join(t.replace("-", " ").title() for t in tacticas) or "N/A",
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        }
    return indice


def cargar_indice_mitre() -> None:
    """Descarga el bundle STIX completo. Si falla, usa el fallback local."""
    global _indice_tecnicas
    try:
        req = urllib.request.Request(
            CONFIG["mitre_stix_url"], headers={"User-Agent": "Sentinel-X/2.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            bundle = json.loads(resp.read().decode())
        nuevo_indice = _construir_indice_desde_stix(bundle)
        with _lock:
            _indice_tecnicas = nuevo_indice
        logger.info("Índice MITRE ATT&CK cargado: %d técnicas.", len(nuevo_indice))
    except Exception as exc:
        logger.warning("No se pudo descargar MITRE STIX (%s). Usando fallback local.", exc)
        with _lock:
            _indice_tecnicas = {
                tid: {**info, "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}
                for tid, info in _FALLBACK_TECNICAS.items()
            }


def info_tecnica(tecnica_id: str) -> dict | None:
    """Devuelve {nombre, tactica, url} para un ID de técnica, o None si no se conoce."""
    if not tecnica_id:
        return None
    with _lock:
        return _indice_tecnicas.get(tecnica_id.strip().upper())


def extraer_tecnicas_de_alerta_suricata(evento_eve: dict) -> list[str]:
    """
    Extrae IDs de técnica MITRE de un evento eve.json de Suricata.
    Soporta el campo metadata.mitre_technique_id (lista) y variantes en
    el texto de la firma como 'MITRE_T1071' (algunas reglas ET lo incluyen
    directamente en el nombre de la firma).
    """
    tecnicas = []
    alerta = evento_eve.get("alert", {})
    metadata = alerta.get("metadata", {})

    valores = metadata.get("mitre_technique_id", [])
    if isinstance(valores, str):
        valores = [valores]
    tecnicas.extend(v for v in valores if v.upper().startswith("T") and not v.upper().startswith("TA"))

    firma = alerta.get("signature", "")
    if "T1" in firma:
        tecnicas.extend(re.findall(r"T1\d{3}(?:\.\d{3})?", firma))

    return list(dict.fromkeys(tecnicas))  # dedup preservando orden


def num_tecnicas_cargadas() -> int:
    with _lock:
        return len(_indice_tecnicas)
