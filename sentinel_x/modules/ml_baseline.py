"""
Baseline de comportamiento por host (detección de anomalías no supervisada).

Para cada host con suficiente historial, entrena un IsolationForest sobre
features agregadas en ventanas de 1 minuto: bytes totales, paquetes,
destinos únicos, puertos únicos, hora del día. Una vez entrenado, el
modelo puntúa el comportamiento reciente; puntuaciones muy negativas
indican un patrón que no se parece a "lo normal" para ese host.

Esto es complementario al beaconing (que busca un patrón fijo conocido)
y al fan-out (que busca un umbral fijo): aquí no hay regla explícita,
el modelo aprende qué es normal para CADA host individualmente, por lo
que puede detectar desviaciones que ningún umbral fijo capturaría.
"""


import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from core.config import CONFIG
from core.logger import get_logger

logger = get_logger("ml_baseline")

_modelos_por_host: dict[str, IsolationForest] = {}


def _construir_features(eventos: list[dict]) -> pd.DataFrame:
    """Agrega eventos de tráfico (TLS o LAN) en ventanas de 1 minuto por host origen."""
    if not eventos:
        return pd.DataFrame()

    df = pd.DataFrame(eventos)
    if df.empty or "Origen" not in df.columns or "Timestamp" not in df.columns:
        return pd.DataFrame()

    df["minuto"] = (df["Timestamp"] // 60).astype(int)
    df["hora_del_dia"] = pd.to_datetime(df["Timestamp"], unit="s").dt.hour

    agg = df.groupby(["Origen", "minuto"]).agg(
        bytes_totales=("Tamaño (bytes)", "sum") if "Tamaño (bytes)" in df.columns else ("Timestamp", "count"),
        paquetes=("Timestamp", "count"),
        destinos_unicos=("Destino", "nunique") if "Destino" in df.columns else ("Timestamp", "count"),
        puertos_unicos=("Puerto", "nunique") if "Puerto" in df.columns else ("Timestamp", "count"),
        hora_del_dia=("hora_del_dia", "first"),
    ).reset_index()

    return agg


def entrenar_baseline(eventos: list[dict]) -> dict[str, int]:
    """
    Entrena un modelo por host con suficiente historial.
    Devuelve {host: n_muestras_usadas} de los hosts entrenados.
    """
    features = _construir_features(eventos)
    if features.empty:
        return {}

    entrenados = {}
    min_muestras = CONFIG["ml_min_muestras_entrenamiento"]
    cols_features = ["bytes_totales", "paquetes", "destinos_unicos", "puertos_unicos", "hora_del_dia"]

    for host, grupo in features.groupby("Origen"):
        if len(grupo) < min_muestras:
            continue
        X = grupo[cols_features].fillna(0)
        modelo = IsolationForest(
            contamination=CONFIG["ml_contaminacion"],
            random_state=42,
            n_estimators=100,
        )
        modelo.fit(X)
        _modelos_por_host[host] = modelo
        entrenados[host] = len(grupo)

    logger.info("Baseline entrenado para %d hosts.", len(entrenados))
    return entrenados


def detectar_anomalias(eventos_recientes: list[dict]) -> pd.DataFrame:
    """
    Puntúa el comportamiento reciente contra los modelos ya entrenados.
    Solo evalúa hosts que tienen un modelo (entrenar_baseline debe correr antes).
    """
    if not _modelos_por_host:
        return pd.DataFrame()

    features = _construir_features(eventos_recientes)
    if features.empty:
        return pd.DataFrame()

    cols_features = ["bytes_totales", "paquetes", "destinos_unicos", "puertos_unicos", "hora_del_dia"]
    resultados = []

    for host, grupo in features.groupby("Origen"):
        modelo = _modelos_por_host.get(host)
        if modelo is None:
            continue

        X = grupo[cols_features].fillna(0)
        scores = modelo.decision_function(X)
        predicciones = modelo.predict(X)  # -1 = anomalía, 1 = normal

        for idx, (score, pred) in enumerate(zip(scores, predicciones)):
            if pred == -1:
                fila = grupo.iloc[idx]
                resultados.append({
                    "Host": host,
                    "Minuto": int(fila["minuto"]),
                    "Score anomalía": round(float(score), 4),
                    "Bytes en ventana": int(fila["bytes_totales"]),
                    "Destinos únicos": int(fila["destinos_unicos"]),
                    "Puertos únicos": int(fila["puertos_unicos"]),
                    "Severidad": "Alta" if score < -0.3 else "Media",
                })

    if not resultados:
        return pd.DataFrame()
    return pd.DataFrame(resultados).sort_values("Score anomalía").reset_index(drop=True)


def hosts_con_modelo_entrenado() -> list[str]:
    return list(_modelos_por_host.keys())


def guardar_modelos(ruta: str) -> None:
    joblib.dump(_modelos_por_host, ruta)


def cargar_modelos(ruta: str) -> bool:
    global _modelos_por_host
    try:
        _modelos_por_host = joblib.load(ruta)
        return True
    except (FileNotFoundError, EOFError):
        return False
