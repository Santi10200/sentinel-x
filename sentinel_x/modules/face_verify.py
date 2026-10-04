"""
Verificación facial 1:1 sobre imágenes locales (laboratorio educativo).

Responde a una única pregunta: "¿estas dos fotos son de la misma persona?".
No busca, no indexa y no compara contra bases de datos externas; solo trabaja
con archivos que el usuario aporta y sobre los que tiene consentimiento.

Pipeline:
  1. Detección  -> DeepFace localiza el rostro (se exige exactamente uno).
  2. Embedding  -> el rostro se convierte en un vector (ArcFace por defecto).
  3. Distancia  -> distancia coseno entre los dos vectores.
  4. Decisión   -> misma persona si distancia <= umbral.

El módulo de evaluación calcula FAR (falsos aceptados) y FRR (falsos
rechazados) para un barrido de umbrales y el EER (punto donde se igualan),
que es lo que de verdad importa al auditar un sistema biométrico: un
"match" nunca es una prueba de identidad, solo una probabilidad con error.

Uso (desde sentinel_x/):
  python -m modules.face_verify verificar foto_a.jpg foto_b.jpg
  python -m modules.face_verify evaluar pares.csv
    pares.csv -> columnas: img1,img2,misma_persona (1/0)
"""

import argparse
import csv
import sys

import numpy as np
import pandas as pd

from core.logger import get_logger

logger = get_logger("face_verify")

MODELO_DEFAULT = "ArcFace"
DETECTOR_DEFAULT = "retinaface"

# Umbrales de distancia coseno de referencia publicados por DeepFace.
# Son un punto de partida: calibra siempre con `evaluar` sobre tus datos.
UMBRALES_REFERENCIA = {
    "ArcFace": 0.68,
    "Facenet512": 0.30,
    "Facenet": 0.40,
    "VGG-Face": 0.68,
    "SFace": 0.593,
}

_cache_embeddings: dict[tuple[str, str, str], np.ndarray] = {}


class ErrorRostro(ValueError):
    """La imagen no contiene exactamente un rostro utilizable."""


def obtener_embedding(
    ruta: str,
    modelo: str = MODELO_DEFAULT,
    detector: str = DETECTOR_DEFAULT,
) -> np.ndarray:
    clave = (ruta, modelo, detector)
    if clave in _cache_embeddings:
        return _cache_embeddings[clave]

    # Import diferido: DeepFace arrastra TensorFlow y tarda en cargar.
    from deepface import DeepFace

    try:
        rostros = DeepFace.represent(
            img_path=ruta,
            model_name=modelo,
            detector_backend=detector,
            enforce_detection=True,
        )
    except ValueError as e:
        raise ErrorRostro(f"{ruta}: no se detectó ningún rostro") from e

    # Verificación 1:1 => una foto con varias caras es ambigua, se rechaza.
    if len(rostros) != 1:
        raise ErrorRostro(f"{ruta}: se esperaba 1 rostro y hay {len(rostros)}")

    vector = np.asarray(rostros[0]["embedding"], dtype=np.float64)
    _cache_embeddings[clave] = vector
    return vector


def distancia_coseno(a: np.ndarray, b: np.ndarray) -> float:
    a = np.asarray(a, dtype=np.float64)
    b = np.asarray(b, dtype=np.float64)
    norma = np.linalg.norm(a) * np.linalg.norm(b)
    if norma == 0:
        raise ValueError("embedding nulo: no se puede calcular la distancia")
    return float(1.0 - np.dot(a, b) / norma)


def verificar(
    ruta_a: str,
    ruta_b: str,
    modelo: str = MODELO_DEFAULT,
    detector: str = DETECTOR_DEFAULT,
    umbral: float | None = None,
) -> dict:
    if umbral is None:
        umbral = UMBRALES_REFERENCIA.get(modelo, 0.40)

    distancia = distancia_coseno(
        obtener_embedding(ruta_a, modelo, detector),
        obtener_embedding(ruta_b, modelo, detector),
    )
    return {
        "img1": ruta_a,
        "img2": ruta_b,
        "modelo": modelo,
        "distancia": round(distancia, 4),
        "umbral": umbral,
        "misma_persona": distancia <= umbral,
    }


# ── Evaluación ───────────────────────────────────────────────────────────


def metricas_por_umbral(
    distancias: list[float],
    etiquetas: list[bool],
    umbrales: list[float] | np.ndarray,
) -> pd.DataFrame:
    """
    FAR = impostores aceptados / total impostores
    FRR = genuinos rechazados / total genuinos
    """
    d = np.asarray(distancias, dtype=np.float64)
    y = np.asarray(etiquetas, dtype=bool)
    n_genuinos = int(y.sum())
    n_impostores = int((~y).sum())
    if n_genuinos == 0 or n_impostores == 0:
        raise ValueError("se necesitan pares genuinos y pares impostores")

    filas = []
    for u in umbrales:
        aceptado = d <= u
        far = float((aceptado & ~y).sum() / n_impostores)
        frr = float((~aceptado & y).sum() / n_genuinos)
        filas.append({"umbral": float(u), "FAR": far, "FRR": frr})
    return pd.DataFrame(filas)


def calcular_eer(tabla: pd.DataFrame) -> dict:
    """Umbral donde |FAR - FRR| es mínimo (aproximación discreta del EER)."""
    idx = (tabla["FAR"] - tabla["FRR"]).abs().idxmin()
    fila = tabla.loc[idx]
    return {
        "umbral": float(fila["umbral"]),
        "EER": float((fila["FAR"] + fila["FRR"]) / 2),
    }


def evaluar(
    pares: list[tuple[str, str, bool]],
    modelo: str = MODELO_DEFAULT,
    detector: str = DETECTOR_DEFAULT,
    umbrales: np.ndarray | None = None,
) -> tuple[pd.DataFrame, dict, list[dict]]:
    if umbrales is None:
        umbrales = np.round(np.arange(0.0, 1.01, 0.01), 2)

    distancias, etiquetas, descartados = [], [], []
    for ruta_a, ruta_b, misma in pares:
        try:
            emb_a = obtener_embedding(ruta_a, modelo, detector)
            emb_b = obtener_embedding(ruta_b, modelo, detector)
        except ErrorRostro as e:
            logger.warning(f"Par descartado: {e}")
            descartados.append({"img1": ruta_a, "img2": ruta_b, "motivo": str(e)})
            continue
        distancias.append(distancia_coseno(emb_a, emb_b))
        etiquetas.append(misma)

    tabla = metricas_por_umbral(distancias, etiquetas, umbrales)
    return tabla, calcular_eer(tabla), descartados


def leer_pares_csv(ruta: str) -> list[tuple[str, str, bool]]:
    with open(ruta, newline="", encoding="utf-8") as f:
        return [
            (fila["img1"], fila["img2"], fila["misma_persona"].strip() in ("1", "true", "True"))
            for fila in csv.DictReader(f)
        ]


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verificación facial 1:1 sobre imágenes locales")
    parser.add_argument("--modelo", default=MODELO_DEFAULT, choices=sorted(UMBRALES_REFERENCIA))
    parser.add_argument("--detector", default=DETECTOR_DEFAULT)
    sub = parser.add_subparsers(dest="comando", required=True)

    p_ver = sub.add_parser("verificar", help="compara dos imágenes")
    p_ver.add_argument("img1")
    p_ver.add_argument("img2")
    p_ver.add_argument("--umbral", type=float)

    p_eval = sub.add_parser("evaluar", help="FAR/FRR/EER sobre un CSV de pares")
    p_eval.add_argument("csv")
    p_eval.add_argument("--salida", help="guarda la tabla FAR/FRR en CSV")

    args = parser.parse_args(argv)

    if args.comando == "verificar":
        try:
            r = verificar(args.img1, args.img2, args.modelo, args.detector, args.umbral)
        except ErrorRostro as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
        veredicto = "MISMA persona" if r["misma_persona"] else "DISTINTA persona"
        print(f"{veredicto}  (distancia={r['distancia']}, umbral={r['umbral']}, modelo={r['modelo']})")
        return 0

    tabla, eer, descartados = evaluar(leer_pares_csv(args.csv), args.modelo, args.detector)
    print(f"Pares descartados: {len(descartados)}")
    print(f"EER ≈ {eer['EER']:.2%} con umbral {eer['umbral']}")
    if args.salida:
        tabla.to_csv(args.salida, index=False)
        print(f"Tabla FAR/FRR guardada en {args.salida}")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
