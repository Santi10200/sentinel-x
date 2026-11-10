"""Priorización explicable de incidentes mediante contexto de activos.

La severidad describe la evidencia técnica observada. Esta capa no la altera:
calcula una prioridad operativa separada combinando la evidencia ya
correlacionada con el valor/exposición del activo y las vulnerabilidades que
ya conoce Sentinel-X. Su salida siempre conserva los factores que llevaron a
la recomendación para que el analista pueda revisarla.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


_PUNTOS_SEVERIDAD = {"Crítica": 55, "Alta": 40, "Media": 25, "Baja": 10}
_TIPOS_SENSIBLES = {
    "servidor", "nas", "router", "firewall", "switch", "plc", "industrial",
    "cámara", "camara", "impresora", "iot", "domótica", "domotica",
}
_PUERTOS_SENSIBLES = {22, 3389, 445, 5432, 3306, 1433, 27017, 6379, 9200}


def _texto(host: dict[str, Any]) -> str:
    return " ".join(str(host.get(campo, "")).lower() for campo in (
        "tipo", "dispositivo", "nombre", "hostname", "etiqueta", "notas",
    ))


def _puertos(host: dict[str, Any]) -> set[int]:
    detalle = str(host.get("puertos_abiertos", ""))
    resultado: set[int] = set()
    for parte in detalle.replace("/udp", "/tcp").split(","):
        try:
            resultado.add(int(parte.strip().split("/")[0]))
        except (ValueError, IndexError):
            continue
    return resultado


def _indice_por_ip(filas: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    indice: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fila in filas or []:
        ip = str(fila.get("ip") or fila.get("IP") or "")
        if ip:
            indice[ip].append(fila)
    return indice


def _nivel(puntaje: int) -> str:
    if puntaje >= 85:
        return "P1 · atención inmediata"
    if puntaje >= 65:
        return "P2 · investigar hoy"
    if puntaje >= 40:
        return "P3 · revisar planificado"
    return "P4 · vigilar"


def _es_kev(vulnerabilidad: dict[str, Any]) -> bool:
    """Normaliza el entero SQLite y posibles cadenas de una importación CSV."""
    return str(vulnerabilidad.get("kev", "")).strip().lower() in {"1", "true", "sí", "si"}


def _cvss_alto(vulnerabilidad: dict[str, Any]) -> bool:
    try:
        return float(vulnerabilidad.get("cvss") or 0) >= 9
    except (TypeError, ValueError):
        return False


def enriquecer(
    incidentes: list[dict[str, Any]], inventario: list[dict[str, Any]],
    vulnerabilidades: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Devuelve incidentes con ``riesgo_contextual`` y una prioridad analista.

    Solo las vulnerabilidades marcadas como probables (o KEV) aportan puntos.
    Así se evita convertir candidatos meramente teóricos en urgencias.
    """
    activos = {str(h.get("ip")): h for h in inventario or [] if h.get("ip")}
    vulns_por_ip = _indice_por_ip(vulnerabilidades)
    resultado: list[dict[str, Any]] = []

    for incidente in incidentes:
        item = dict(incidente)
        ip = str(item.get("ip_principal", ""))
        activo = activos.get(ip, {})
        factores: list[str] = []
        puntaje = _PUNTOS_SEVERIDAD.get(item.get("severidad"), 25)

        # La confianza modula la orden de trabajo, nunca la severidad técnica.
        confianza = int(item.get("confianza", 0) or 0)
        if confianza >= 80:
            puntaje += 10
            factores.append("corroboración alta")
        elif confianza >= 55:
            puntaje += 5
            factores.append("corroboración media")

        texto_activo = _texto(activo)
        if any(tipo in texto_activo for tipo in _TIPOS_SENSIBLES):
            puntaje += 15
            factores.append("activo de infraestructura o IoT")
        puertos = _puertos(activo)
        if puertos & _PUERTOS_SENSIBLES:
            puntaje += 10
            factores.append("servicio administrativo o de datos expuesto")

        vulns = vulns_por_ip.get(ip, [])
        # KEV sin una aplicación posible en este activo sigue siendo una pista,
        # no una urgencia automática.
        kev = any(_es_kev(v) and v.get("aplicabilidad", "Probable") != "Improbable" for v in vulns)
        probable = [v for v in vulns if v.get("aplicabilidad", "Probable") == "Probable"]
        if kev:
            puntaje += 25
            factores.append("CVE en CISA KEV")
        elif any(_cvss_alto(v) for v in probable):
            puntaje += 15
            factores.append("CVE probable con CVSS ≥ 9")
        elif probable:
            puntaje += 8
            factores.append("CVE probable asociado al activo")

        puntaje = min(100, puntaje)
        nombre = activo.get("hostname") or activo.get("nombre") or ""
        item.update({
            "riesgo_contextual": puntaje,
            "prioridad_analista": _nivel(puntaje),
            "factores_riesgo": factores or ["sin contexto adicional disponible"],
            "activo_contexto": {
                "nombre": nombre,
                "tipo": activo.get("tipo") or activo.get("dispositivo") or "Desconocido",
                "puertos": sorted(puertos),
                "vulnerabilidades_probables": len(probable),
                "kev": kev,
            },
        })
        resultado.append(item)

    return sorted(resultado, key=lambda i: (-i["riesgo_contextual"], -i.get("confianza", 0), -i.get("timestamp", 0)))
