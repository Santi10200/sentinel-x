"""Normalización y controles de calidad para la telemetría de Sentinel-X.

Los sensores no comparten el mismo esquema: Scapy usa títulos en español,
Suricata entrega alertas y Zeek conserva nombres de campo propios. Este módulo
crea una representación canónica para auditoría sin obligar a reescribir los
detectores existentes. También filtra registros estructuralmente inválidos y
duplicados *dentro de la misma fuente*; eventos equivalentes de fuentes
distintas se conservan porque son evidencia independiente para correlación.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import time
from collections.abc import Mapping
from typing import Any


FUENTES = ("tls", "lan", "suricata", "zeek")


def _texto(valor: Any) -> str:
    return str(valor).strip() if valor is not None else ""


def _timestamp(valor: Any) -> float | None:
    try:
        numero = float(valor)
    except (TypeError, ValueError):
        return None
    return numero if math.isfinite(numero) and numero > 0 else None


def _ip(valor: Any) -> str:
    texto = _texto(valor)
    if not texto:
        return ""
    try:
        return str(ipaddress.ip_address(texto))
    except ValueError:
        return ""


def _puerto(valor: Any) -> int | None:
    try:
        puerto = int(valor)
    except (TypeError, ValueError):
        return None
    return puerto if 0 <= puerto <= 65535 else None


def _campos_evento(fuente: str, evento: Mapping[str, Any]) -> dict[str, Any]:
    """Extrae campos equivalentes de cada sensor sin modificar su evidencia."""
    if fuente == "tls":
        return {
            "tipo": "flujo_tls", "timestamp": evento.get("Timestamp"),
            "origen": evento.get("Origen"), "destino": evento.get("Destino"),
            "puerto_origen": evento.get("Puerto origen"), "puerto_destino": evento.get("Puerto"),
            "protocolo": "TLS", "bytes": evento.get("Tamaño (bytes)"),
            "contexto": {"sni": evento.get("SNI", ""), "ja3": evento.get("JA3", "")},
        }
    if fuente == "lan":
        return {
            "tipo": "flujo_lan", "timestamp": evento.get("Timestamp"),
            "origen": evento.get("Origen"), "destino": evento.get("Destino"),
            "puerto_origen": evento.get("Puerto origen"), "puerto_destino": evento.get("Puerto"),
            "protocolo": evento.get("Proto"), "bytes": evento.get("Tamaño (bytes)"),
            "contexto": {"inicio": bool(evento.get("Inicio"))},
        }
    if fuente == "suricata":
        return {
            "tipo": "alerta_ids", "timestamp": evento.get("Timestamp"),
            "origen": evento.get("IP Origen"), "destino": evento.get("IP Destino"),
            "puerto_origen": evento.get("Puerto Origen"), "puerto_destino": evento.get("Puerto Destino"),
            "protocolo": evento.get("Proto"), "bytes": None,
            "contexto": {"firma": evento.get("Firma", ""), "gravedad": evento.get("Gravedad"),
                         "mitre": evento.get("MITRE Técnica", "")},
        }
    # Zeek se almacena con los nombres originales de su JSON para preservar
    # evidencia y compatibilidad con conn/dns/ssl/http/files/notice.
    return {
        "tipo": _texto(evento.get("tipo_log")) or "zeek", "timestamp": evento.get("ts") or evento.get("timestamp_local"),
        "origen": evento.get("id.orig_h"), "destino": evento.get("id.resp_h"),
        "puerto_origen": evento.get("id.orig_p"), "puerto_destino": evento.get("id.resp_p"),
        "protocolo": evento.get("proto"),
        "bytes": _bytes_zeek(evento),
        "contexto": {"query": evento.get("query", ""), "server_name": evento.get("server_name", ""),
                     "host": evento.get("host", ""), "notice": evento.get("note", "")},
    }


def _bytes_zeek(evento: Mapping[str, Any]) -> int | None:
    try:
        return max(0, int(evento.get("orig_bytes") or 0) + int(evento.get("resp_bytes") or 0))
    except (TypeError, ValueError):
        return None


def normalizar_evento(fuente: str, evento: Mapping[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Devuelve un evento canónico o la razón por la que no puede usarse."""
    if fuente not in FUENTES:
        return None, "fuente_desconocida"
    if not isinstance(evento, Mapping):
        return None, "no_es_objeto"
    campos = _campos_evento(fuente, evento)
    timestamp = _timestamp(campos["timestamp"])
    if timestamp is None:
        return None, "timestamp_invalido"

    bytes_ = campos["bytes"]
    try:
        bytes_ = int(bytes_) if bytes_ is not None else None
    except (TypeError, ValueError):
        bytes_ = None
    if bytes_ is not None and bytes_ < 0:
        return None, "bytes_invalidos"

    canonico = {
        "fuente": fuente, "tipo": campos["tipo"], "timestamp": timestamp,
        "origen": _ip(campos["origen"]), "destino": _ip(campos["destino"]),
        "puerto_origen": _puerto(campos["puerto_origen"]),
        "puerto_destino": _puerto(campos["puerto_destino"]),
        "protocolo": _texto(campos["protocolo"]).upper(), "bytes": bytes_,
        "contexto": {k: v for k, v in campos["contexto"].items() if v not in (None, "")},
    }
    # Una alerta puede no contener IP (p. ej. aviso del motor IDS), pero un
    # flujo sin ambos extremos no es útil para análisis de red.
    if canonico["tipo"] in ("flujo_tls", "flujo_lan") and not (canonico["origen"] and canonico["destino"]):
        return None, "extremos_invalidos"
    return canonico, None


def huella_evento(evento: Mapping[str, Any]) -> str:
    """Huella estable para deduplicar la misma observación dentro de una fuente."""
    partes = (
        evento["fuente"], evento["tipo"], round(float(evento["timestamp"]), 3), evento["origen"], evento["destino"],
        evento["puerto_origen"], evento["puerto_destino"], evento["protocolo"], evento["bytes"],
        tuple(sorted((str(k), str(v)) for k, v in evento["contexto"].items())),
    )
    return hashlib.sha256(repr(partes).encode("utf-8")).hexdigest()


def preparar_foto(fuentes: Mapping[str, list[dict]], ahora: float | None = None) -> dict[str, Any]:
    """Normaliza una foto de buffers y devuelve evidencia, originales aceptados y métricas."""
    ahora = time.time() if ahora is None else ahora
    aceptados: dict[str, list[dict]] = {fuente: [] for fuente in FUENTES}
    canonicos: list[dict[str, Any]] = []
    resumen: dict[str, dict[str, Any]] = {}

    for fuente in FUENTES:
        vistos: set[str] = set()
        metricas = {"recibidos": 0, "aceptados": 0, "duplicados": 0, "invalidos": 0,
                    "motivos_invalidos": {}, "ultimo_evento": None, "edad_segundos": None}
        for original in fuentes.get(fuente, []):
            metricas["recibidos"] += 1
            canonico, motivo = normalizar_evento(fuente, original)
            if canonico is None:
                metricas["invalidos"] += 1
                metricas["motivos_invalidos"][motivo] = metricas["motivos_invalidos"].get(motivo, 0) + 1
                continue
            huella = huella_evento(canonico)
            if huella in vistos:
                metricas["duplicados"] += 1
                continue
            vistos.add(huella)
            metricas["aceptados"] += 1
            metricas["ultimo_evento"] = max(metricas["ultimo_evento"] or 0, canonico["timestamp"])
            aceptados[fuente].append(dict(original))
            canonicos.append({**canonico, "id_evento": huella})
        if metricas["ultimo_evento"] is not None:
            metricas["edad_segundos"] = max(0.0, ahora - metricas["ultimo_evento"])
        resumen[fuente] = metricas

    return {"aceptados": aceptados, "eventos": sorted(canonicos, key=lambda e: e["timestamp"]), "resumen": resumen}
