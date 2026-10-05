import os

import pytest

from core.config import CONFIG
from modules import ml_baseline as ml

HOST = "10.0.0.9"
INICIO = 1_700_000_000 // 60 * 60  # alineado a minuto


@pytest.fixture(autouse=True)
def limpio(db, tmp_path, monkeypatch):
    monkeypatch.setattr(ml, "_modelos_por_host", {})
    monkeypatch.setattr(ml, "_ultimo_minuto_persistido", None)
    monkeypatch.setitem(CONFIG, "ml_modelos_path", str(tmp_path / "modelos.joblib"))
    monkeypatch.setitem(CONFIG, "ml_min_muestras_entrenamiento", 30)


def _minuto(m, destinos=3, bytes_por_evento=500, eventos=10):
    return [{"Origen": HOST, "Destino": f"10.0.0.{100 + i % destinos}", "Puerto": 443,
             "Timestamp": INICIO + m * 60 + i, "Tamaño (bytes)": bytes_por_evento}
            for i in range(eventos)]


def _trafico_normal(minutos=120):
    return [e for m in range(minutos) for e in _minuto(m, destinos=3 + m % 2)]


def test_persistir_solo_minutos_cerrados():
    eventos = _minuto(0) + _minuto(1)
    guardadas = ml.persistir_features(eventos, ahora=INICIO + 60 + 30)  # el minuto 1 sigue abierto
    assert guardadas == 1
    assert len(ml.cargar_features(0)) == 1
    assert ml.persistir_features(eventos, ahora=INICIO + 125) == 2  # rehace el 0 (idempotente) + el 1
    assert len(ml.cargar_features(0)) == 2


def test_entrena_detecta_y_explica():
    ml.persistir_features(_trafico_normal(), ahora=INICIO + 10_000)
    entrenados = ml.entrenar_desde_features(ml.cargar_features(0))
    assert entrenados[HOST] >= 100

    # Barrido: 60 destinos distintos en un minuto.
    df = ml.detectar_anomalias(_minuto(200, destinos=60, eventos=60))
    assert len(df) == 1
    assert "destinos distintos" in df.iloc[0]["Motivo"]
    # Mismo patrón y misma franja horaria que el entrenamiento (2 h, minutos 0-119): normal.
    assert ml.detectar_anomalias(_minuto(61, destinos=4)).empty


def test_horario_atipico_es_anomalo():
    ml.entrenar_desde_features(ml.agregar_por_minuto(_trafico_normal()))
    # Mismo volumen y destinos, pero 12 h después: actividad fuera del horario habitual.
    df = ml.detectar_anomalias(_minuto(12 * 60 + 30, destinos=4))
    assert len(df) == 1 and "horario sin tráfico" in df.iloc[0]["Motivo"]


def test_no_reporta_minutos_normales_marcados_por_contamination():
    datos = ml.agregar_por_minuto(_trafico_normal())
    ml.entrenar_desde_features(datos)
    # El propio conjunto de entrenamiento: el modelo marca ~5 % como -1 por diseño,
    # pero ninguno se aleja 3σ ni cae fuera de horario, así que no se reporta nada.
    assert (ml._modelos_por_host[HOST]["modelo"].predict(ml._con_hora(datos)[ml.FEATURES]) == -1).any()
    assert ml.puntuar(datos).empty


def test_guardar_y_cargar_modelos():
    ml.entrenar_desde_features(ml.agregar_por_minuto(_trafico_normal()))
    ml.guardar_modelos()
    assert oct(os.stat(CONFIG["ml_modelos_path"]).st_mode & 0o777) == "0o600"
    ml._modelos_por_host.clear()
    assert ml.cargar_modelos()
    assert ml.hosts_con_modelo_entrenado() == [HOST]


def test_descarta_modelos_de_otra_version(monkeypatch):
    ml.entrenar_desde_features(ml.agregar_por_minuto(_trafico_normal()))
    ml.guardar_modelos()
    monkeypatch.setattr(ml, "VERSION_FEATURES", 999)
    assert not ml.cargar_modelos()


def test_reentreno_excluye_anomalias_previas():
    ml.entrenar_desde_features(ml.agregar_por_minuto(_trafico_normal()))
    # 20 minutos de ataque mezclados con el tráfico normal.
    ataque = [e for m in range(300, 320) for e in _minuto(m, destinos=60, eventos=60)]
    datos = ml.agregar_por_minuto(_trafico_normal() + ataque)
    ml.entrenar_desde_features(datos)
    assert ml._modelos_por_host[HOST]["muestras"] <= len(datos) - 20
    assert not ml.detectar_anomalias(_minuto(400, destinos=60, eventos=60)).empty
