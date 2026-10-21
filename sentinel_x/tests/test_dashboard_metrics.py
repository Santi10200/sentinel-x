import pandas as pd

from modules import dashboard_metrics


def test_riesgo_prioriza_incidentes_observados_sobre_postura():
    riesgo = dashboard_metrics.riesgo_global([{"severidad": "Alta"}], pd.DataFrame([{"Severidad": "Crítica"}]))
    assert riesgo["puntuacion"] == 36
    assert riesgo["nivel"] == "Moderado"


def test_riesgo_vacio_es_bajo_y_explicable():
    riesgo = dashboard_metrics.riesgo_global([], pd.DataFrame())
    assert riesgo["puntuacion"] == 0
    assert riesgo["nivel"] == "Bajo"
