from modules import event_quality


def test_normaliza_y_deduplica_solo_dentro_de_la_misma_fuente():
    evento = {"Origen": "10.0.0.2", "Destino": "10.0.0.3", "Puerto": 445,
              "Proto": "tcp", "Timestamp": 100.0, "Tamaño (bytes)": 60, "Inicio": True}
    resultado = event_quality.preparar_foto({"lan": [evento, dict(evento)], "tls": [], "suricata": [], "zeek": []}, ahora=120)

    assert len(resultado["aceptados"]["lan"]) == 1
    assert resultado["resumen"]["lan"]["duplicados"] == 1
    assert resultado["eventos"][0]["protocolo"] == "TCP"
    assert resultado["resumen"]["lan"]["edad_segundos"] == 20


def test_rechaza_flujo_sin_extremos_y_conserva_razon():
    resultado = event_quality.preparar_foto({"tls": [{"Timestamp": 10, "Origen": "no-ip", "Destino": ""}],
                                               "lan": [], "suricata": [], "zeek": []}, ahora=20)

    assert resultado["aceptados"]["tls"] == []
    assert resultado["resumen"]["tls"]["motivos_invalidos"] == {"extremos_invalidos": 1}


def test_normaliza_evidencia_zeek_sin_perder_su_contexto():
    zeek = {"tipo_log": "dns", "ts": 50.0, "id.orig_h": "10.0.0.8", "id.resp_h": "1.1.1.1",
            "id.orig_p": 51000, "id.resp_p": 53, "proto": "udp", "query": "example.org"}
    resultado = event_quality.preparar_foto({"tls": [], "lan": [], "suricata": [], "zeek": [zeek]}, ahora=60)

    evento = resultado["eventos"][0]
    assert evento["tipo"] == "dns"
    assert evento["origen"] == "10.0.0.8"
    assert evento["contexto"]["query"] == "example.org"
