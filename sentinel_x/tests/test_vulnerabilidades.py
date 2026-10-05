import json

from modules import device_profiler, threat_intel, vulnerabilidades as v

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<ports>
 <port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5">
   <cpe>cpe:/a:openbsd:openssh:8.2p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
 <port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="Apache httpd" version="2.4.49"><cpe>cpe:/a:apache:http_server:2.4.49</cpe></service></port>
 <port protocol="tcp" portid="81"><state state="closed"/><service name="hosts2-ns"/></port>
</ports>
<os><osmatch name="Linux 5.0 - 5.14" accuracy="98"/></os>
</host></nmaprun>"""


def _respuesta(*cves):
    return {"totalResults": len(cves), "vulnerabilities": [{"cve": c} for c in cves]}


CVE_APACHE = {
    "id": "CVE-2021-41773", "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49"}],
    "metrics": {"cvssMetricV31": [
        {"source": "x@y", "type": "Secondary", "cvssData": {"baseScore": 9.8}},
        {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"baseScore": 7.5}},
    ]},
}
CVE_V2 = {"id": "CVE-2008-0001", "descriptions": [{"lang": "es", "value": "Antigua"}],
          "metrics": {"cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}}]}}
CVE_RECHAZADO = {"id": "CVE-2020-9999", "vulnStatus": "Rejected", "descriptions": [], "metrics": {}}


def test_parsear_nmap_xml():
    r = device_profiler.parsear_nmap_xml(NMAP_XML)
    assert r["os_detectado"] == "Linux 5.0 - 5.14"
    assert r["puertos_abiertos"] == "22/tcp, 80/tcp"
    detalle = json.loads(r["servicios_detalle"])
    assert detalle[0]["cpes"][0] == "cpe:/a:openbsd:openssh:8.2p1"
    assert detalle[1]["producto"] == "Apache httpd"


def test_conversion_cpe():
    assert v.cpe22_a_23("cpe:/a:apache:http_server:2.4.49") == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
    assert v.cpe22_a_23("cpe:/o:linux:linux_kernel") is None  # sin versión: demasiado amplio
    assert v.cpe22_a_23("no-es-cpe") is None
    assert v.candidatos_cpe("cpe:/a:openbsd:openssh:8.2p1") == [
        "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*",
        "cpe:2.3:a:openbsd:openssh:8.2:p1:*:*:*:*:*:*",
    ]


def test_parsear_respuesta_nvd():
    cves = v.parsear_respuesta_nvd(_respuesta(CVE_APACHE, CVE_V2, CVE_RECHAZADO))
    assert [c["cve"] for c in cves] == ["CVE-2021-41773", "CVE-2008-0001"]
    assert cves[0]["cvss"] == 7.5  # prioriza la métrica Primary del NVD
    assert cves[1]["cvss"] == 5.0 and cves[1]["descripcion"] == "Antigua"


def test_severidad():
    assert v.severidad_desde_cvss(9.8) == "Crítica"
    assert v.severidad_desde_cvss(7.5) == "Alta"
    assert v.severidad_desde_cvss(2.0) == "Baja"
    assert v.severidad_desde_cvss(2.0, en_kev=True) == "Crítica"


def test_busqueda_completa_cache_y_kev(db, monkeypatch):
    monkeypatch.setattr(threat_intel, "_cves_explotados_activamente", {"CVE-2021-41773"})
    perfil = {"ip": "10.0.0.2", "mac": "aa", **device_profiler.parsear_nmap_xml(NMAP_XML)}
    db.upsert_inventario(perfil)
    inventario = db.consultar("SELECT * FROM inventario_red")

    llamadas = []

    def falso_nvd(cpe):
        llamadas.append(cpe)
        if "http_server" in cpe:
            return _respuesta(CVE_APACHE)
        if ":8.2:p1:" in cpe:
            return _respuesta(CVE_V2)
        return {}  # variante exacta '8.2p1' no está en el diccionario

    resumen = v.buscar_vulnerabilidades(inventario, peticion=falso_nvd)
    assert resumen == {"servicios": 2, "consultados": 2, "fallidos": 0, "cves": 2, "kev": 1}
    filas = {f["cve"]: f for f in v.vulnerabilidades_guardadas()}
    assert filas["CVE-2021-41773"]["severidad"] == "Crítica" and filas["CVE-2021-41773"]["kev"] == 1
    assert filas["CVE-2008-0001"]["cpe"].endswith(":8.2:p1:*:*:*:*:*:*")

    # Segunda búsqueda: todo sale de la caché, sin red.
    n = len(llamadas)
    v.buscar_vulnerabilidades(inventario, peticion=falso_nvd)
    assert len(llamadas) == n

    hallazgos = v.hallazgos_postura(v.vulnerabilidades_guardadas())
    apache = next(h for h in hallazgos if "80/tcp" in h["Detalle"])
    assert apache["Severidad"] == "Crítica" and "CISA KEV" in apache["Detalle"]
    assert "ID.RA-02" in apache["NIST CSF"]


def test_fallo_de_red_conserva_resultados_previos(db):
    db.ejecutar("INSERT INTO vulnerabilidades (timestamp, ip, puerto, cve, severidad, kev) "
                "VALUES (1, '10.0.0.2', 80, 'CVE-X', 'Alta', 0)")
    perfil = {"ip": "10.0.0.2", "mac": "aa", **device_profiler.parsear_nmap_xml(NMAP_XML)}
    db.upsert_inventario(perfil)
    resumen = v.buscar_vulnerabilidades(db.consultar("SELECT * FROM inventario_red"), peticion=lambda c: None)
    assert resumen["fallidos"] == 2
    assert [f["cve"] for f in v.vulnerabilidades_guardadas()] == ["CVE-X"]


def test_reescaneo_sin_nmap_no_borra_servicios(db):
    db.upsert_inventario({"ip": "10.0.0.2", "mac": "aa", **device_profiler.parsear_nmap_xml(NMAP_XML)})
    db.upsert_inventario({"ip": "10.0.0.2", "mac": "aa", "fabricante": "X"})
    fila = db.consultar("SELECT * FROM inventario_red")[0]
    assert fila["puertos_abiertos"] == "22/tcp, 80/tcp" and fila["fabricante"] == "X"
