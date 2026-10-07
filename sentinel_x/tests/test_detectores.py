import pandas as pd

from modules import beaconing, correlation_engine, lateral_movement, sniffer, threat_intel
from modules.wifi_security import parsear_rsn


def _evento(origen, destino, puerto, ts, inicio=True, sport=50000):
    return {"Origen": origen, "Destino": destino, "Puerto": puerto, "Puerto origen": sport,
            "Proto": "TCP", "Inicio": inicio, "Timestamp": ts, "Tamaño (bytes)": 60}


def test_fanout_detecta_barrido_interno():
    eventos = [_evento("10.0.0.5", f"10.0.0.{i}", 445, 1000 + i) for i in range(10, 30)]
    df = lateral_movement.detectar_fanout(eventos, umbral_hosts=8, ventana_seg=120)
    assert list(df["IP origen"]) == ["10.0.0.5"]


def test_fanout_ignora_respuestas_de_servidor():
    # Un gateway respondiendo a 20 clientes no es un escaneo.
    eventos = [_evento("10.0.0.1", f"10.0.0.{i}", 51000 + i, 1000 + i, inicio=False, sport=53)
               for i in range(10, 30)]
    assert lateral_movement.detectar_fanout(eventos, umbral_hosts=8, ventana_seg=120).empty


def test_fanout_ignora_multicast_y_broadcast():
    eventos = [_evento("10.0.0.5", f"224.0.0.{i}", 5353, 1000 + i) for i in range(20)]
    eventos.append(_evento("10.0.0.5", "255.255.255.255", 67, 1001))
    assert lateral_movement.detectar_fanout(eventos, umbral_hosts=3, ventana_seg=120).empty


def test_inicio_udp():
    assert sniffer.es_inicio_udp(50000, 53)       # cliente -> DNS
    assert not sniffer.es_inicio_udp(53, 50000)   # respuesta DNS
    assert sniffer.es_inicio_udp(5353, 5353)      # mDNS entre pares


def test_beaconing_usa_solo_inicios_de_conexion():
    flujos = []
    # Beacon real: ClientHello cada 60 s exactos.
    for i in range(8):
        flujos.append({"Origen": "10.0.0.7", "Destino": "203.0.113.9", "SNI": "c2.example",
                       "JA3": "abc", "Timestamp": 1000 + 60 * i, "Tamaño (bytes)": 500})
    # Segmentos de datos de una sesión normal a intervalos casi perfectos: no deben contar.
    for i in range(50):
        flujos.append({"Origen": "10.0.0.8", "Destino": "198.51.100.1", "SNI": "Cifrado/Desconocido",
                       "JA3": "N/A", "Timestamp": 1000 + 0.01 * i, "Tamaño (bytes)": 1400})
    df = beaconing.detectar(flujos, min_paquetes=5, umbral_cv=0.1)
    assert list(df["IP Local"]) == ["10.0.0.7"]
    assert df.iloc[0]["Severidad"] == "Media"


def test_correlacion_atribuye_beacon_al_host_local():
    df_beacons = pd.DataFrame([{"IP Local": "10.0.0.7", "IP Destino": "203.0.113.9",
                                "Destino (SNI)": "c2.example", "Severidad": "Media", "Razones": "x"}])
    df_fanout = pd.DataFrame([{"IP origen": "10.0.0.7", "Hosts contactados": 20,
                               "Ventana (seg)": 120, "Severidad": "Alta", "MITRE": "T1046"}])
    incidentes = correlation_engine.correlacionar(df_beacons, df_fanout, pd.DataFrame(), pd.DataFrame(), [])
    assert len(incidentes) == 1
    inc = incidentes[0]
    assert inc["ip_principal"] == "10.0.0.7"
    assert inc["num_fuentes"] == 2
    assert inc["severidad"] == "Crítica"  # Alta + 1 fuente adicional


def test_ti_dominio_por_sufijo(monkeypatch):
    monkeypatch.setattr(threat_intel, "_dominios_maliciosos", {"malo.com"})
    assert threat_intel.verificar_dominio("x.y.malo.com")
    assert threat_intel.verificar_dominio("MALO.com.")
    assert threat_intel.verificar_dominio("nomalo.com") is None
    assert threat_intel.verificar_dominio("") is None


def test_rsn_pmf_y_wpa3():
    sae_ccmp = (
        (1).to_bytes(2, "little") + b"\x00\x0f\xac\x04"
        + (1).to_bytes(2, "little") + b"\x00\x0f\xac\x04"
        + (1).to_bytes(2, "little") + b"\x00\x0f\xac\x08"
        + (0x00C0).to_bytes(2, "little")
    )
    rsn = parsear_rsn(sae_ccmp)
    assert rsn["cifrado"] == "WPA3-Personal"
    assert rsn["pmf"] == "Requerido"
