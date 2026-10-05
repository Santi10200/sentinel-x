import time

import pytest


def test_rotacion_borra_antiguos_y_conserva_casos(db):
    viejo = time.time() - 30 * 86400
    db.insertar("alertas_ids", {"timestamp": viejo, "firma": "vieja"})
    db.insertar("alertas_ids", {"timestamp": time.time(), "firma": "nueva"})
    db.insertar("casos", {"creado": viejo, "actualizado": viejo, "estado": "Cerrado"})
    db.rotar_si_excede_limite()
    assert [f["firma"] for f in db.consultar("SELECT firma FROM alertas_ids")] == ["nueva"]
    assert len(db.consultar("SELECT id FROM casos")) == 1


def test_rotacion_por_tamano(db, monkeypatch):
    from core.config import CONFIG
    ahora = time.time()
    for i in range(10):
        db.insertar("flujos_tls", {"timestamp": ahora + i, "sni": str(i)})
    monkeypatch.setitem(CONFIG, "db_max_tamano_mb", 0)
    db.rotar_si_excede_limite()
    restantes = [f["sni"] for f in db.consultar("SELECT sni FROM flujos_tls ORDER BY timestamp")]
    assert restantes == [str(i) for i in range(5, 10)]


def test_insertar_valida_tabla_y_columnas(db):
    with pytest.raises(ValueError):
        db.insertar("sqlite_master", {"x": 1})
    with pytest.raises(ValueError):
        db.insertar("alertas_ids", {"timestamp) VALUES (1); DROP TABLE casos; --": 1})
