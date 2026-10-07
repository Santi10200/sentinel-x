import pandas as pd

from modules import informe, nist_csf, postura, respuesta_incidentes as ri


INVENTARIO = [
    {"ip": "10.0.0.2", "tipo": "Router", "puertos_abiertos": "23/tcp, 80/tcp", "servicios": "telnet"},
    {"ip": "10.0.0.3", "tipo": "NAS", "puertos_abiertos": "22/tcp, 443/tcp", "servicios": "ssh"},
]


def test_servicios_inseguros():
    h = postura.servicios_inseguros(INVENTARIO)
    detalles = {(x["Activo"], x["Severidad"]) for x in h}
    assert ("10.0.0.2", "Crítica") in detalles  # Telnet
    assert ("10.0.0.2", "Baja") in detalles     # HTTP
    assert not any(x["Activo"] == "10.0.0.3" for x in h)


def test_protocolos_en_claro_ignora_respuestas():
    eventos = [
        {"Origen": "10.0.0.9", "Destino": "10.0.0.2", "Puerto": 23, "Inicio": True},
        {"Origen": "10.0.0.2", "Destino": "10.0.0.9", "Puerto": 23, "Inicio": False},
    ]
    h = postura.protocolos_en_claro(eventos)
    assert len(h) == 1 and h[0]["Activo"] == "10.0.0.9"


def test_wifi_debil():
    redes = [
        {"ssid": "Casa", "bssid": "aa", "cifrado": "WEP (vulnerable)"},
        {"ssid": "Ofi", "bssid": "bb", "cifrado": "WPA2-Personal", "pmf": "No anunciado",
         "cipher_suites": "CCMP-128 (AES), TKIP"},
        {"ssid": "Bien", "bssid": "cc", "cifrado": "WPA3-Personal", "pmf": "Requerido"},
    ]
    h = postura.wifi_debil(redes)
    por_red = {}
    for x in h:
        por_red.setdefault(x["Activo"], []).append(x["Severidad"])
    assert por_red["Casa (aa)"] == ["Crítica"]
    assert sorted(por_red["Ofi (bb)"]) == ["Baja", "Media"]
    assert "Bien (cc)" not in por_red


def test_nist_sin_datos_no_rompe_y_no_puntua_lo_desconocido():
    df = nist_csf.evaluar(nist_csf.Contexto())
    assert set(df["Subcategoría"]) == set(nist_csf.SUBCATEGORIAS)
    puntos = nist_csf.puntuaciones(df)
    gv = puntos[puntos["Función"].str.startswith("Gobernar")].iloc[0]
    assert pd.isna(gv["Puntuación"])  # todo manual y sin responder


def test_nist_con_evidencia():
    ahora = 1_000_000.0
    ctx = nist_csf.Contexto(
        sensores={"TLS": True, "LAN": True, "Suricata": True, "Zeek": False},
        inventario=INVENTARIO, inventario_ultima_vez=ahora - 3600,
        eventos_lan=100, flujos_tls=50, alertas_ids=3,
        ti_habilitado=True, ti_indicadores=1000, mitre_tecnicas=600,
        analisis_ejecutado=True,
        incidentes=[{"ip_principal": "10.0.0.7", "severidad": "Alta"}],
        postura=postura.evaluar(INVENTARIO, [], []),
        autoevaluacion={"GV.PO-01": nist_csf.CUMPLE},
        ahora=ahora,
    )
    df = nist_csf.evaluar(ctx).set_index("Subcategoría")
    assert df.loc["ID.AM-01", "Estado"] == nist_csf.CUMPLE
    assert df.loc["ID.RA-01", "Estado"] == nist_csf.NO_CUMPLE  # Telnet crítico
    assert df.loc["DE.CM-01", "Estado"] == nist_csf.CUMPLE
    assert df.loc["DE.AE-08", "Estado"] == nist_csf.NO_CUMPLE  # incidente alto sin caso
    assert df.loc["GV.PO-01", "Estado"] == nist_csf.CUMPLE
    assert df.loc["ID.RA-01", "Recomendación"]
    global_ = nist_csf.puntuacion_global(nist_csf.puntuaciones(df.reset_index()))
    assert 0 <= global_ <= 100


def test_ciclo_de_vida_de_caso(db):
    incidente = {"ip_principal": "10.0.0.7", "severidad": "Crítica", "fuentes": ["Beaconing C2"],
                 "mitre_tecnicas": ["T1071.001"], "hallazgos": [{"descripcion": "beacon"}]}
    caso_id, nuevo = ri.abrir_caso(incidente, autor="ana")
    assert nuevo
    assert ri.abrir_caso(incidente) == (caso_id, False)  # no duplica

    caso = ri.obtener_caso(caso_id)
    assert caso["prioridad"].startswith("P1")
    assert caso["fuentes"] == ["Beaconing C2"]

    ri.cambiar_estado(caso_id, "Contenido", "Host aislado", "ana")
    ri.agregar_nota(caso_id, "Dominio bloqueado", "ana")
    ri.cambiar_estado(caso_id, "Cerrado", "Lecciones aprendidas", "ana")
    estados = [h["estado"] for h in ri.historial(caso_id)]
    assert estados == ["Detectado", "Contenido", "Contenido", "Cerrado"]
    assert ri.caso_abierto_para_ip("10.0.0.7") is None
    assert ri.abrir_caso(incidente)[1]  # cerrado -> se abre uno nuevo

    import pytest
    with pytest.raises(ValueError):
        ri.cambiar_estado(caso_id, "Inventado", "")


def test_informe_escapa_html():
    resultado = {
        "timestamp": 1_000_000.0, "inventario": [], "incidentes": [], "casos": [],
        "df_postura": postura.evaluar([], [], [{"ssid": "<script>alert(1)</script>", "bssid": "x",
                                                "cifrado": "Abierta"}]),
    }
    df_nist = nist_csf.evaluar(nist_csf.Contexto())
    resultado.update({"df_nist": df_nist, "df_nist_puntos": nist_csf.puntuaciones(df_nist), "nist_global": None})
    salida = informe.generar_html(resultado, red="10.0.0.0/24", organizacion="<b>Org</b>")
    assert "<script>alert(1)</script>" not in salida
    assert "&lt;script&gt;" in salida
    assert "&lt;b&gt;Org&lt;/b&gt;" in salida
