import collections
import json

import pytest

from core import state
from modules import evidence_import


@pytest.fixture()
def buffers_limpios(monkeypatch):
    monkeypatch.setattr(state, "eventos_zeek", collections.deque(maxlen=20))
    monkeypatch.setattr(state, "eventos_lan", collections.deque(maxlen=20))


def test_importa_conn_y_lo_entrega_al_pipeline(db, buffers_limpios):
    linea = json.dumps({
        "ts": 1710000000.5,
        "id": {"orig_h": "10.0.0.8", "orig_p": 50000, "resp_h": "198.51.100.2", "resp_p": 443},
        "proto": "tcp", "orig_bytes": 100, "resp_bytes": 900,
    }).encode()
    resultado = evidence_import.importar_zeek_jsonl("conn.log", linea + b"\nno-json")

    assert resultado["aceptados"] == 1
    assert resultado["rechazados"] == 1
    assert len(state.eventos_zeek) == 1
    assert state.eventos_lan[0]["Destino"] == "198.51.100.2"
    assert state.eventos_lan[0]["Tamaño (bytes)"] == 1000
    guardado = evidence_import.importaciones_recientes()
    assert guardado[0]["sha256"] == resultado["sha256"]
    assert guardado[0]["archivo"] == "conn.log"


def test_rechaza_tipo_de_log_no_soportado(buffers_limpios):
    with pytest.raises(ValueError, match="no admitido"):
        evidence_import.importar_zeek_jsonl("unknown.log", b'{}')


def test_no_convierte_conn_sin_ips(db, buffers_limpios):
    resultado = evidence_import.importar_zeek_jsonl("conn.log", b'{"ts": 1, "id": {}}')
    assert resultado["aceptados"] == 1
    assert resultado["eventos_lan"] == 0
    assert not state.eventos_lan
