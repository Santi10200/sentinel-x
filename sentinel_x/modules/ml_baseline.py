"""
Baseline de comportamiento por host (detección de anomalías no supervisada).

Para cada host con suficiente historial se entrena un IsolationForest sobre
features agregadas por minuto: bytes, paquetes, destinos únicos, puertos
únicos y hora del día (codificada en seno/coseno para que 23:59 y 00:00
queden cerca). Puntuaciones muy negativas indican un patrón que no se
parece a "lo normal" para ESE host.

Ciclo de vida (hilo `hilo_baseline_ml`, lanzado por el orquestador):
  1. Cada minuto agrega los minutos ya cerrados de los buffers en memoria
     y los guarda en la tabla `ml_features`. Así el baseline sobrevive a
     reinicios y puede cubrir 24 h aunque los buffers solo guarden minutos.
  2. Cada `ml_reentreno_min` reentrena con la ventana
     `ml_ventana_entrenamiento_horas` y guarda los modelos en disco.
  3. Al reentrenar, los minutos que el modelo anterior ya consideraba
     anómalos se excluyen: si no, un ataque sostenido acabaría
     "aprendiéndose" como normal (envenenamiento del baseline).

Esto complementa al beaconing (patrón fijo conocido) y al fan-out
(umbral fijo): aquí no hay regla explícita.
"""

import math
import os
import tempfile
import threading
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from core import database, state
from core.config import CONFIG
from core.logger import get_logger

logger = get_logger("ml_baseline")

FEATURES_BASE = ["bytes_totales", "paquetes", "destinos_unicos", "puertos_unicos"]
FEATURES = FEATURES_BASE + ["hora_sin", "hora_cos"]
# Cambia si cambian las features: los modelos guardados con otra versión se descartan.
VERSION_FEATURES = 2

_ETIQUETAS = {
    "bytes_totales": "volumen de bytes", "paquetes": "nº de paquetes",
    "destinos_unicos": "destinos distintos", "puertos_unicos": "puertos distintos",
}

_lock = threading.Lock()
# {host: {"modelo": IsolationForest, "muestras": int, "entrenado": float,
#         "media": dict, "desv": dict}}
_modelos_por_host: dict[str, dict] = {}
_ultimo_minuto_persistido: int | None = None


# ── Features ─────────────────────────────────────────────────────────────

def agregar_por_minuto(eventos: list[dict]) -> pd.DataFrame:
    """Eventos (TLS o LAN) -> una fila por (host origen, minuto) con FEATURES_BASE."""
    if not eventos:
        return pd.DataFrame()
    df = pd.DataFrame(eventos)
    if df.empty or not {"Origen", "Timestamp"}.issubset(df.columns):
        return pd.DataFrame()

    df["minuto"] = (df["Timestamp"] // 60).astype(int)
    if "Tamaño (bytes)" not in df.columns:
        df["Tamaño (bytes)"] = 0
    for col in ("Destino", "Puerto"):
        if col not in df.columns:
            df[col] = None

    return df.groupby(["Origen", "minuto"]).agg(
        bytes_totales=("Tamaño (bytes)", "sum"),
        paquetes=("Timestamp", "count"),
        destinos_unicos=("Destino", "nunique"),
        puertos_unicos=("Puerto", "nunique"),
    ).reset_index().rename(columns={"Origen": "host"})


def _hora_local(minutos: pd.Series) -> pd.Series:
    return minutos.map(lambda m: time.localtime(int(m) * 60).tm_hour)


def _con_hora(df: pd.DataFrame) -> pd.DataFrame:
    """Añade hora local en coordenadas circulares."""
    df = df.copy()
    horas = df["minuto"].map(lambda m: (lambda t: t.tm_hour + t.tm_min / 60)(time.localtime(int(m) * 60)))
    angulo = 2 * math.pi * horas.astype(float) / 24
    df["hora_sin"] = np.sin(angulo)
    df["hora_cos"] = np.cos(angulo)
    return df


def persistir_features(eventos: list[dict], ahora: float | None = None) -> int:
    """
    Guarda en SQLite los minutos ya cerrados (el minuto en curso aún recibe
    tráfico). Idempotente: re-procesar un minuto lo sobrescribe. Devuelve
    el nº de filas guardadas.
    """
    global _ultimo_minuto_persistido
    minuto_actual = int((ahora or time.time()) // 60)
    df = agregar_por_minuto(eventos)
    if df.empty:
        return 0
    df = df[df["minuto"] < minuto_actual]
    if _ultimo_minuto_persistido is not None:
        # El último minuto ya guardado puede haber recibido eventos tardíos: se rehace.
        df = df[df["minuto"] >= _ultimo_minuto_persistido]
    if df.empty:
        return 0

    database.ejecutar_varios("""
        INSERT INTO ml_features
            (timestamp, host, minuto, bytes_totales, paquetes, destinos_unicos, puertos_unicos)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(host, minuto) DO UPDATE SET
            bytes_totales=excluded.bytes_totales, paquetes=excluded.paquetes,
            destinos_unicos=excluded.destinos_unicos, puertos_unicos=excluded.puertos_unicos
    """, [
        (float(f.minuto * 60), f.host, int(f.minuto), float(f.bytes_totales), float(f.paquetes),
         float(f.destinos_unicos), float(f.puertos_unicos))
        for f in df.itertuples(index=False)
    ])
    _ultimo_minuto_persistido = int(df["minuto"].max())
    return len(df)


def cargar_features(desde_ts: float, hasta_ts: float | None = None) -> pd.DataFrame:
    filas = database.consultar(
        "SELECT host, minuto, bytes_totales, paquetes, destinos_unicos, puertos_unicos "
        "FROM ml_features WHERE timestamp >= ? AND timestamp < ? ORDER BY minuto",
        (desde_ts, hasta_ts if hasta_ts is not None else float("inf")),
    )
    return pd.DataFrame(filas)


# ── Entrenamiento ────────────────────────────────────────────────────────

def entrenar_desde_features(features: pd.DataFrame, filtrar_anomalias_previas: bool = True) -> dict[str, int]:
    """Entrena un modelo por host con al menos `ml_min_muestras_entrenamiento` minutos."""
    if features.empty:
        return {}
    features = _con_hora(features)
    min_muestras = CONFIG["ml_min_muestras_entrenamiento"]
    nuevos, entrenados = {}, {}

    with _lock:
        previos = dict(_modelos_por_host)

    for host, grupo in features.groupby("host"):
        X = grupo[FEATURES].fillna(0)
        previo = previos.get(host)
        if filtrar_anomalias_previas and previo is not None:
            normales = previo["modelo"].predict(X) == 1
            X = X[normales]
        if len(X) < min_muestras:
            continue
        modelo = IsolationForest(
            contamination=CONFIG["ml_contaminacion"], random_state=42, n_estimators=100,
        )
        modelo.fit(X)
        media = X[FEATURES_BASE].mean()
        # Suelo del 10 % de la media: una métrica casi constante no debe producir
        # "25000σ" por una variación pequeña y ocultar la que de verdad cambió.
        desv = X[FEATURES_BASE].std(ddof=0).combine(media.abs() * 0.1, max).clip(lower=1.0)
        nuevos[host] = {
            "modelo": modelo, "muestras": len(X), "entrenado": time.time(),
            "media": media.to_dict(), "desv": desv.to_dict(),
            "horas": sorted(set(_hora_local(grupo.loc[X.index, "minuto"]))),
        }
        entrenados[host] = len(X)

    with _lock:
        _modelos_por_host.update(nuevos)
    logger.info("Baseline entrenado para %d hosts.", len(entrenados))
    return entrenados


def entrenar_desde_historial() -> dict[str, int]:
    """Reentrena con la ventana configurada de features persistidas y guarda en disco."""
    desde = time.time() - CONFIG["ml_ventana_entrenamiento_horas"] * 3600
    entrenados = entrenar_desde_features(cargar_features(desde))
    if entrenados:
        guardar_modelos()
    state.estado_hilos["ml_baseline"]["ultimo_entrenamiento"] = time.time()
    return entrenados


def entrenar_baseline(eventos: list[dict]) -> dict[str, int]:
    """Compatibilidad: entrena directamente desde eventos en memoria."""
    return entrenar_desde_features(agregar_por_minuto(eventos), filtrar_anomalias_previas=False)


# ── Detección ────────────────────────────────────────────────────────────

def explicar(fila: pd.Series, info: dict) -> tuple[list[str], float]:
    """
    Motivos concretos de la anomalía y la mayor desviación (en σ).

    IsolationForest con `contamination` marca por diseño una fracción fija
    de minutos como anómalos aunque sean normales. Solo se reporta una
    anomalía si además hay algo explicable: una métrica a >= `ml_umbral_sigma`
    de lo habitual del host, o tráfico en una hora en la que ese host nunca
    tuvo actividad durante el entrenamiento.
    """
    umbral = CONFIG["ml_umbral_sigma"]
    motivos, max_z = [], 0.0
    zs = {f: (fila[f] - info["media"][f]) / info["desv"][f] for f in FEATURES_BASE}
    for f, z in sorted(zs.items(), key=lambda kv: -abs(kv[1])):
        max_z = max(max_z, abs(z))
        if abs(z) >= umbral:
            direccion = "más" if z > 0 else "menos"
            motivos.append(f"{abs(z):.0f}σ {direccion} {_ETIQUETAS[f]} ({fila[f]:.0f} vs {info['media'][f]:.0f} habitual)")
    horas = info.get("horas")
    hora = time.localtime(int(fila["minuto"]) * 60).tm_hour
    if horas is not None and hora not in horas:
        motivos.append(f"actividad a las {hora:02d}h, horario sin tráfico en el baseline")
    return motivos, max_z


def puntuar(features: pd.DataFrame) -> pd.DataFrame:
    """Puntúa features por minuto contra los modelos entrenados."""
    with _lock:
        modelos = dict(_modelos_por_host)
    if not modelos or features.empty:
        return pd.DataFrame()

    features = _con_hora(features)
    resultados = []
    for host, grupo in features.groupby("host"):
        info = modelos.get(host)
        if info is None:
            continue
        X = grupo[FEATURES].fillna(0)
        scores = info["modelo"].decision_function(X)
        predicciones = info["modelo"].predict(X)  # -1 = anomalía
        for (_, fila), score, pred in zip(grupo.iterrows(), scores, predicciones):
            if pred != -1:
                continue
            motivos, max_z = explicar(fila, info)
            if not motivos:
                continue  # dentro del margen normal del host: falso positivo del contamination
            resultados.append({
                "Host": host,
                "Minuto": time.strftime("%Y-%m-%d %H:%M", time.localtime(int(fila["minuto"]) * 60)),
                "Score anomalía": round(float(score), 4),
                "Bytes en ventana": int(fila["bytes_totales"]),
                "Destinos únicos": int(fila["destinos_unicos"]),
                "Puertos únicos": int(fila["puertos_unicos"]),
                "Motivo": "; ".join(motivos),
                "Severidad": "Alta" if max_z >= 10 else "Media",
            })
    if not resultados:
        return pd.DataFrame()
    return pd.DataFrame(resultados).sort_values("Score anomalía").reset_index(drop=True)


def detectar_anomalias(eventos_recientes: list[dict]) -> pd.DataFrame:
    """Puntúa eventos en memoria (agregados por minuto)."""
    return puntuar(agregar_por_minuto(eventos_recientes))


def detectar_anomalias_recientes(minutos: int | None = None) -> pd.DataFrame:
    """Puntúa los últimos N minutos persistidos (por defecto `ml_ventana_deteccion_min`)."""
    minutos = minutos or CONFIG["ml_ventana_deteccion_min"]
    return puntuar(cargar_features(time.time() - minutos * 60))


# ── Estado y persistencia ────────────────────────────────────────────────

def hosts_con_modelo_entrenado() -> list[str]:
    with _lock:
        return list(_modelos_por_host.keys())


def resumen_modelos() -> pd.DataFrame:
    with _lock:
        modelos = dict(_modelos_por_host)
    return pd.DataFrame([{
        "Host": host, "Minutos de entrenamiento": info["muestras"],
        "Entrenado": time.strftime("%Y-%m-%d %H:%M", time.localtime(info["entrenado"])),
        "Bytes/min habitual": round(info["media"]["bytes_totales"]),
        "Destinos/min habitual": round(info["media"]["destinos_unicos"], 1),
    } for host, info in sorted(modelos.items())])


def guardar_modelos(ruta: str | None = None) -> None:
    """Escritura atómica (archivo temporal + rename) con permisos 0600."""
    ruta = ruta or CONFIG["ml_modelos_path"]
    directorio = os.path.dirname(ruta) or "."
    os.makedirs(directorio, exist_ok=True)
    with _lock:
        contenido = {"version": VERSION_FEATURES, "modelos": dict(_modelos_por_host)}
    fd, tmp = tempfile.mkstemp(dir=directorio, prefix=".ml_modelos_")
    try:
        os.close(fd)
        os.chmod(tmp, 0o600)
        joblib.dump(contenido, tmp)
        os.replace(tmp, ruta)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def cargar_modelos(ruta: str | None = None) -> bool:
    """
    Carga modelos guardados por Sentinel-X. joblib usa pickle: solo debe
    leerse un archivo escrito por esta aplicación (por eso se crea 0600).
    """
    global _modelos_por_host
    ruta = ruta or CONFIG["ml_modelos_path"]
    try:
        contenido = joblib.load(ruta)
    except (FileNotFoundError, EOFError):
        return False
    except Exception as exc:
        logger.warning("No se pudieron cargar los modelos ML de %s: %s", ruta, exc)
        return False
    if not isinstance(contenido, dict) or contenido.get("version") != VERSION_FEATURES:
        logger.info("Modelos ML guardados con otra versión de features: se reentrenarán.")
        return False
    with _lock:
        _modelos_por_host = dict(contenido["modelos"])
    logger.info("Modelos ML cargados: %d hosts.", len(_modelos_por_host))
    return True


def hilo_baseline_ml() -> None:
    """Persiste features cada minuto y reentrena periódicamente."""
    estado = state.estado_hilos["ml_baseline"]
    estado["activo"] = True
    cargar_modelos()
    ultimo_entreno = 0.0
    while True:
        try:
            eventos = (state.snapshot(state.eventos_lan, state.lock_eventos_lan)
                       + state.snapshot(state.flujos_tls, state.lock_flujos_tls))
            estado["procesados"] += persistir_features(eventos)
            if time.time() - ultimo_entreno >= CONFIG["ml_reentreno_min"] * 60:
                entrenar_desde_historial()
                ultimo_entreno = time.time()
            estado["error"] = None
        except Exception as exc:
            logger.error("Error en hilo de baseline ML: %s", exc)
            estado["error"] = str(exc)
        time.sleep(60)
