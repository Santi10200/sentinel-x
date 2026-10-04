"""Tests de la parte matemática de face_verify (no requieren DeepFace)."""

import numpy as np
import pytest

from modules import face_verify


def test_distancia_coseno_identicos_es_cero():
    v = np.array([0.3, -1.2, 4.0])
    assert face_verify.distancia_coseno(v, v) == pytest.approx(0.0)


def test_distancia_coseno_ortogonales_es_uno():
    assert face_verify.distancia_coseno([1, 0], [0, 1]) == pytest.approx(1.0)


def test_distancia_coseno_vector_nulo():
    with pytest.raises(ValueError):
        face_verify.distancia_coseno([0, 0], [1, 1])


def test_metricas_far_frr():
    # 2 genuinos (0.2, 0.5) y 2 impostores (0.4, 0.9)
    tabla = face_verify.metricas_por_umbral(
        [0.2, 0.5, 0.4, 0.9], [True, True, False, False], [0.3, 0.45, 1.0]
    )
    assert tabla.to_dict("records") == [
        {"umbral": 0.3, "FAR": 0.0, "FRR": 0.5},
        {"umbral": 0.45, "FAR": 0.5, "FRR": 0.5},
        {"umbral": 1.0, "FAR": 1.0, "FRR": 0.0},
    ]


def test_metricas_requiere_ambas_clases():
    with pytest.raises(ValueError):
        face_verify.metricas_por_umbral([0.1, 0.2], [True, True], [0.5])


def test_eer():
    tabla = face_verify.metricas_por_umbral(
        [0.2, 0.5, 0.4, 0.9], [True, True, False, False], [0.3, 0.45, 1.0]
    )
    assert face_verify.calcular_eer(tabla) == {"umbral": 0.45, "EER": 0.5}


def test_evaluar_descarta_pares_sin_rostro(monkeypatch):
    embeddings = {"a1": [1, 0], "a2": [0.9, 0.1], "b1": [0, 1]}

    def falso_embedding(ruta, modelo, detector):
        if ruta not in embeddings:
            raise face_verify.ErrorRostro(f"{ruta}: no se detectó ningún rostro")
        return np.array(embeddings[ruta], dtype=float)

    monkeypatch.setattr(face_verify, "obtener_embedding", falso_embedding)
    pares = [("a1", "a2", True), ("a1", "b1", False), ("a1", "vacia", True)]
    tabla, eer, descartados = face_verify.evaluar(pares)

    assert len(descartados) == 1
    assert eer["EER"] == 0.0


def test_leer_pares_csv(tmp_path):
    f = tmp_path / "pares.csv"
    f.write_text("img1,img2,misma_persona\na.jpg,b.jpg,1\na.jpg,c.jpg,0\n", encoding="utf-8")
    assert face_verify.leer_pares_csv(str(f)) == [
        ("a.jpg", "b.jpg", True),
        ("a.jpg", "c.jpg", False),
    ]
