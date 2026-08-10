"""Análisis pasivo de seguridad Wi-Fi a partir de beacons y probe responses."""

try:
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
except ImportError:  # Permite probar el parser RSN sin una tarjeta/captura Scapy instalada.
    Dot11 = Dot11Beacon = Dot11Elt = Dot11ProbeResp = None

_RSN_OUI = b"\x00\x0f\xac"
_CIPHER_NAMES = {
    1: "WEP-40", 2: "TKIP", 4: "CCMP-128 (AES)", 5: "WEP-104",
    6: "BIP-CMAC-128", 8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256",
}
_AKM_NAMES = {
    1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK",
    5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE",
    11: "Suite-B-192", 12: "802.1X-SHA384", 18: "OWE",
}


def _suite_name(suite: bytes, names: dict[int, str]) -> str:
    if len(suite) != 4:
        return "Truncada"
    if suite[:3] == _RSN_OUI:
        return names.get(suite[3], f"RSN-{suite[3]}")
    return f"OUI-{suite[:3].hex(':')}-{suite[3]}"


def _leer_u16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise ValueError("Elemento RSN truncado")
    return int.from_bytes(data[offset:offset + 2], "little"), offset + 2


def parsear_rsn(payload: bytes) -> dict:
    """Parsea RSN por longitudes; no busca firmas binarias de forma ambigua."""
    offset = 0
    version, offset = _leer_u16(payload, offset)
    if version != 1 or offset + 4 > len(payload):
        raise ValueError("Versión RSN no soportada o elemento truncado")
    group_cipher = _suite_name(payload[offset:offset + 4], _CIPHER_NAMES)
    offset += 4
    pairwise_count, offset = _leer_u16(payload, offset)
    end = offset + pairwise_count * 4
    if end > len(payload):
        raise ValueError("Lista pairwise RSN truncada")
    pairwise = [_suite_name(payload[i:i + 4], _CIPHER_NAMES) for i in range(offset, end, 4)]
    offset = end
    akm_count, offset = _leer_u16(payload, offset)
    end = offset + akm_count * 4
    if end > len(payload):
        raise ValueError("Lista AKM RSN truncada")
    akms = [_suite_name(payload[i:i + 4], _AKM_NAMES) for i in range(offset, end, 4)]
    offset = end
    capabilities = 0
    if offset + 2 <= len(payload):
        capabilities, offset = _leer_u16(payload, offset)

    # IEEE 802.11 RSN Capabilities: MFPR bit 6 y MFPC bit 7 (no bits 2/3).
    if capabilities & 0x0040:
        pmf = "Requerido"
    elif capabilities & 0x0080:
        pmf = "Soportado"
    else:
        pmf = "No anunciado"

    if "SAE" in akms or "FT-SAE" in akms:
        cifrado = "WPA2/WPA3 transición" if any(a in akms for a in ("PSK", "FT-PSK")) else "WPA3-Personal"
    elif "OWE" in akms:
        cifrado = "WPA3-Enhanced Open (OWE)"
    elif any("802.1X" in a or "Suite-B" in a for a in akms):
        cifrado = "WPA2/WPA3-Enterprise"
    else:
        cifrado = "WPA2-Personal" if "PSK" in akms else "RSN (AKM no reconocido)"
    return {"cifrado": cifrado, "pmf": pmf, "akm_suites": akms, "cipher_suites": [group_cipher, *pairwise]}


def analizar_trama_wifi(pkt) -> dict | None:
    """Devuelve los datos de seguridad de un beacon/probe response, o None."""
    if Dot11 is None:
        return None
    if not (pkt.haslayer(Dot11) and (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp))):
        return None
    bssid = pkt[Dot11].addr3
    if not bssid:
        return None
    ssid = "Oculto"
    rsn_payload = None
    wpa_legacy = False
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        if elt.ID == 0:
            ssid = elt.info.decode("utf-8", errors="replace") or "Oculto"
        elif elt.ID == 48:
            rsn_payload = bytes(elt.info)
        elif elt.ID == 221 and bytes(elt.info).startswith(b"\x00\x50\xf2\x01"):
            wpa_legacy = True
        elt = elt.payload

    resultado = {"bssid": bssid.lower(), "ssid": ssid, "akm_suites": [], "cipher_suites": []}
    if rsn_payload is not None:
        try:
            resultado.update(parsear_rsn(rsn_payload))
        except ValueError as exc:
            resultado.update({"cifrado": "RSN malformado", "pmf": "Desconocido", "error": str(exc)})
    elif wpa_legacy:
        resultado.update({"cifrado": "WPA (legacy)", "pmf": "No anunciado"})
    else:
        cap = pkt[Dot11Beacon].cap if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp].cap
        resultado.update({
            "cifrado": "WEP (vulnerable)" if getattr(cap, "privacy", False) else "Abierta",
            "pmf": "No anunciado",
        })
    return resultado
