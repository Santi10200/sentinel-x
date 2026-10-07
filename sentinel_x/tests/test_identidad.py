import pytest
from scapy.all import BOOTP, DHCP, DNS, DNSRR, IP, UDP, Ether, raw

from core import database
from modules import device_profiler, identidad as idn


@pytest.fixture(autouse=True)
def limpio(db, monkeypatch):
    database.ejecutar("DELETE FROM identidad_obs")
    database.ejecutar("DELETE FROM etiquetas_dispositivo")
    monkeypatch.setattr(idn, "_cache_obs", {})


def _dhcp(mac, opciones):
    pkt = (Ether(src=mac) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
           / BOOTP(op=1, chaddr=bytes.fromhex(mac.replace(":", ""))) / DHCP(options=opciones + ["end"]))
    return Ether(raw(pkt))


def _mdns(ip, registros):
    return Ether(raw(Ether() / IP(src=ip, dst="224.0.0.251") / UDP(sport=5353, dport=5353)
                     / DNS(qr=1, aa=1, an=registros)))


UPNP_TV = """<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
  <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
  <friendlyName>[TV] Samsung Sala</friendlyName><manufacturer>Samsung Electronics</manufacturer>
  <modelName>UN55TU8000</modelName><modelNumber>AllShare1.0</modelNumber>
</device></root>"""


def test_mac_aleatoria():
    assert idn.es_mac_aleatoria("DA:A1:19:00:00:01")
    assert idn.es_mac_aleatoria("6e:00:00:00:00:00")
    assert not idn.es_mac_aleatoria("3c:22:fb:00:00:01")  # OUI real de Apple
    assert not idn.es_mac_aleatoria("03:00:00:00:00:00")  # multicast
    assert not idn.es_mac_aleatoria("")


def test_modelo_apple():
    assert idn.modelo_apple("iPhone15,2")["modelo"] == "iPhone 14 Pro"
    desconocido = idn.modelo_apple("iPhone99,1")
    assert desconocido["modelo"] == "iPhone (iPhone99,1)" and desconocido["tipo"] == "Smartphone"
    assert idn.modelo_apple("MacBookPro18,3")["tipo"] == "PC / portátil"
    assert idn.modelo_apple("AudioAccessory5,1")["modelo"].startswith("HomePod")
    assert idn.modelo_apple("no-apple") is None


@pytest.mark.parametrize("hostname,tipo,marca,modelo", [
    ("Galaxy-A54-5G", "Smartphone", "Samsung", "Galaxy A54 5G"),
    ("Galaxy-Tab-S8", "Tablet", "Samsung", "Galaxy Tab S8"),
    ("Redmi-Note-12", "Smartphone", "Xiaomi", "Redmi Note 12"),
    ("iPhone-de-Ana", "Smartphone", "Apple", ""),
    ("android-1a2b3c4d5e6f", "Smartphone / tablet", "Android (fabricante no anunciado)", ""),
    ("DESKTOP-AB12CD3", "PC / portátil", "", ""),
    ("HP3C2A1B", "Impresora", "HP", ""),
    ("LGwebOSTV.lan", "Smart TV / streaming", "LG", ""),
])
def test_clasificar_hostname(hostname, tipo, marca, modelo):
    r = idn.clasificar_hostname(hostname)
    assert (r["tipo"], r["fabricante"], r["modelo"]) == (tipo, marca, modelo)


def test_hostname_desconocido():
    assert idn.clasificar_hostname("servidor-casa") is None
    assert idn.clasificar_hostname("") is None


def test_dhcp_android_samsung():
    pkt = _dhcp("da:a1:19:00:00:01", [("message-type", "request"), ("hostname", b"Galaxy-A54-5G"),
                                       ("vendor_class_id", b"android-dhcp-14"),
                                       ("requested_addr", "192.168.1.50"),
                                       ("param_req_list", [1, 3, 6, 15, 26, 28, 51, 58, 59, 43])])
    obs = idn.parsear_dhcp(pkt)
    assert obs["clave"] == "da:a1:19:00:00:01" and obs["ip"] == "192.168.1.50"
    d = obs["datos"]
    assert d["sistema"] == "Android 14" and d["modelo"] == "Galaxy A54 5G" and d["fabricante"] == "Samsung"


def test_dhcp_huellas_sin_vendor_class():
    assert idn.clasificar_dhcp("", [1, 121, 3, 6, 15, 108, 114, 119, 252])["sistema"] == "iOS / macOS"
    assert idn.clasificar_dhcp("", [1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252])["sistema"] == "Windows"
    assert idn.clasificar_dhcp("MSFT 5.0", [])["sistema"] == "Windows"
    assert idn.clasificar_dhcp("udhcp 1.31.1", [])["tipo"] == "IoT / equipo embebido"


def test_mdns_iphone_y_chromecast():
    iphone = _mdns("192.168.1.50", [
        DNSRR(rrname="iPhone de Ana._device-info._tcp.local", type="TXT", rdata=[b"model=iPhone15,2"]),
        DNSRR(rrname="iPhone-de-Ana.local", type="A", rdata="192.168.1.50"),
    ])
    obs = idn.parsear_mdns(iphone[DNS], "192.168.1.50")
    assert obs["clave"] == "ip:192.168.1.50"
    assert obs["datos"]["modelo"] == "iPhone 14 Pro" and obs["datos"]["nombre"] == "iPhone de Ana"
    assert obs["datos"]["hostname"] == "iPhone-de-Ana"

    cast = _mdns("192.168.1.60", [DNSRR(
        rrname="Chromecast-abc._googlecast._tcp.local", type="TXT",
        rdata=[b"md=Chromecast with Google TV", b"fn=TV Sala"])])
    d = idn.parsear_mdns(cast[DNS], "192.168.1.60")["datos"]
    assert d["modelo"] == "Chromecast with Google TV" and d["nombre"] == "TV Sala"
    assert d["tipo"] == "Smart TV / streaming"


def test_upnp_y_ssdp():
    d = idn.parsear_descripcion_upnp(UPNP_TV)
    assert d == {"nombre": "[TV] Samsung Sala", "fabricante": "Samsung Electronics",
                 "modelo": "UN55TU8000 AllShare1.0", "tipo": "Smart TV / streaming"}
    cab = idn.parsear_ssdp("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.70:9197/dmr\r\nSERVER: Samsung\r\n")
    assert cab["location"] == "http://192.168.1.70:9197/dmr"


def test_upnp_no_sigue_urls_ajenas():
    # El LOCATION debe apuntar a la misma IP privada que respondió.
    assert idn.obtener_descripcion_upnp("http://8.8.8.8/x.xml", "8.8.8.8") == {}
    assert idn.obtener_descripcion_upnp("http://192.168.1.99/x.xml", "192.168.1.70") == {}
    assert idn.obtener_descripcion_upnp("file:///etc/passwd", "192.168.1.70") == {}


def test_procesar_paquete_registra_y_fusiona():
    assert idn.procesar_paquete(_dhcp("da:a1:19:00:00:01", [("hostname", b"Galaxy-A54-5G")]))
    assert idn.procesar_paquete(_dhcp("da:a1:19:00:00:01", [("vendor_class_id", b"android-dhcp-14")]))
    obs = idn.observaciones()
    assert len(obs) == 1
    assert obs[0]["datos"]["hostname"] == "Galaxy-A54-5G" and obs[0]["datos"]["sistema"] == "Android 14"


def test_resolver_prioridades():
    host_iphone = {"ip": "192.168.1.50", "mac": "da:a1:19:00:00:01", "tipo": "Desconocido",
                   "fabricante": "MAC privada (aleatoria)", "hostname": ""}
    # Solo la MAC: confianza baja, pero no inventa fabricante.
    r = idn.resolver(host_iphone, [])
    assert r["dispositivo"] == "Smartphone / tablet (MAC privada)" and r["confianza"] == "Baja"
    assert r["marca"] == ""

    obs = [
        {"clave": "da:a1:19:00:00:01", "fuente": "DHCP", "mac": "da:a1:19:00:00:01",
         "datos": {"hostname": "iPhone-de-Ana", "tipo": "Smartphone", "fabricante": "Apple", "sistema": "iOS / macOS"}},
        {"clave": "ip:192.168.1.50", "fuente": "mDNS", "mac": "",
         "datos": {"modelo": "iPhone 14 Pro", "tipo": "Smartphone", "fabricante": "Apple",
                   "sistema": "iOS", "nombre": "iPhone de Ana"}},
    ]
    r = idn.resolver(host_iphone, obs)
    assert (r["modelo"], r["confianza"], r["nombre"], r["sistema"]) == ("iPhone 14 Pro", "Alta", "iPhone de Ana", "iOS")

    r = idn.resolver(host_iphone, obs, {"etiqueta": "Celular de Ana", "tipo": ""})
    assert r["nombre"] == "Celular de Ana" and r["confianza"] == "Manual" and r["modelo"] == "iPhone 14 Pro"


def test_resolver_usa_hostname_del_dns_inverso():
    host = {"ip": "192.168.1.51", "mac": "c8:d3:a3:00:00:09", "tipo": "Router doméstico",
            "fabricante": "TP-Link", "hostname": "Redmi-Note-12.lan", "fuente_hostname": "DNS reverso"}
    r = idn.resolver(host, [])
    assert (r["dispositivo"], r["marca"], r["modelo"], r["confianza"]) == ("Smartphone", "Xiaomi", "Redmi Note 12", "Media")
    assert r["fuente_identidad"] == "DNS reverso"


def test_etiquetas_persisten_y_se_borran():
    idn.guardar_etiqueta("DA:A1:19:00:00:01", "Celular de Ana", "Smartphone", "Ana")
    assert idn.etiquetas()["da:a1:19:00:00:01"]["etiqueta"] == "Celular de Ana"
    idn.guardar_etiqueta("da:a1:19:00:00:01", "", "")
    assert idn.etiquetas() == {}


def test_parsear_oui_nmap_y_wireshark():
    nmap = "000000 Xerox\n3C22FB Apple\n"
    wireshark = "# comentario\n00:00:0C\tCisco\tCisco Systems, Inc\n00:1B:C5:00:00:00/36\tX\tY\nC8:D3:A3\tD-Link\n"
    t = device_profiler.parsear_oui(nmap)
    assert t["3C:22:FB"] == "Apple" and t["00:00:00"] == "Xerox"
    t = device_profiler.parsear_oui(wireshark)
    assert t == {"00:00:0C": "Cisco Systems, Inc", "C8:D3:A3": "D-Link"}
