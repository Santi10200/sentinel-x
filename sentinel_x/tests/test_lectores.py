import json
import threading
import time

from core import state
from core.config import CONFIG
from modules import suricata_reader, zeek_reader

_SLEEP_REAL = time.sleep


def _esperar(condicion, segundos=15):
    limite = time.time() + segundos
    while time.time() < limite:
        if condicion():
            return True
        _SLEEP_REAL(0.1)
    return False


def test_suricata_arranca_despues_que_sentinel(tmp_path, monkeypatch):
    ruta = tmp_path / "eve.json"
    monkeypatch.setitem(CONFIG, "archivo_suricata", str(ruta))
    monkeypatch.setattr(suricata_reader.time, "sleep", lambda s: _SLEEP_REAL(min(s, 0.1)))
    state.alertas_ids.clear()
    threading.Thread(target=suricata_reader.hilo_tail_suricata, daemon=True).start()

    assert _esperar(lambda: "Esperando" in (state.estado_hilos["suricata_tail"]["error"] or ""))
    alerta = {"event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "10.0.0.9",
              "alert": {"severity": 1, "signature": "ET TEST", "category": "x"}}
    ruta.write_text(json.dumps(alerta) + "\n")

    assert _esperar(lambda: len(state.alertas_ids) == 1)
    assert state.estado_hilos["suricata_tail"]["error"] is None


def test_zeek_espera_al_directorio(tmp_path, monkeypatch):
    directorio = tmp_path / "current"
    monkeypatch.setitem(CONFIG, "dir_zeek_logs", str(directorio))
    monkeypatch.setattr(zeek_reader.time, "sleep", lambda s: _SLEEP_REAL(min(s, 0.1)))
    state.eventos_zeek.clear()
    threading.Thread(target=zeek_reader.hilo_watch_zeek, daemon=True).start()

    assert _esperar(lambda: "Esperando" in (state.estado_hilos["zeek_watch"]["error"] or ""))
    directorio.mkdir()
    (directorio / "conn.log").write_text(json.dumps({"ts": 1, "id.orig_h": "10.0.0.5"}) + "\n")
    assert _esperar(lambda: len(state.eventos_zeek) == 1)
