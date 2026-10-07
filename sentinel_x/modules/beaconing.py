"""
Detección de beaconing C2 (Command & Control).

Algoritmo base: agrupa flujos TLS por (origen, destino, SNI, JA3) y mide
el coeficiente de variación (CV = desviación / media) de los intervalos
entre paquetes. CV bajo = comportamiento mecánico, típico de malware
que llama a casa cada N segundos con jitter mínimo.

Mejoras sobre la versión anterior:
  - Solo se miden intervalos entre ClientHello (conexiones nuevas), no
    entre segmentos de una misma sesión TLS.
  - ddof=0 para evitar NaN con pocas muestras.
  - Cruce con Threat Intelligence: si el destino ya es C2 conocido, la
    alerta sube de severidad inmediatamente sin esperar el patrón temporal.
  - Cruce con detección DGA: dominios de alta entropía sobre el mismo
    patrón temporal son una señal combinada mucho más fuerte.
"""

import pandas as pd

from core.config import CONFIG
from core.logger import get_logger
from modules import tls_analysis, threat_intel

logger = get_logger("beaconing")


def detectar(
    flujos: list[dict],
    min_paquetes: int = CONFIG["beacon_min_paquetes"],
    umbral_cv: float = CONFIG["beacon_umbral_cv"],
) -> pd.DataFrame:
    if not flujos:
        return pd.DataFrame()

    df = pd.DataFrame(flujos)
    columnas_req = {"Origen", "Destino", "SNI", "JA3", "Timestamp"}
    if df.empty or not columnas_req.issubset(df.columns):
        return pd.DataFrame()

    # Solo cuentan los inicios de conexión (ClientHello, que es donde hay JA3).
    # Los demás segmentos TLS de una misma sesión llegan a ráfagas y no dicen
    # nada sobre cada cuánto "llama a casa" el host.
    df = df[~df["JA3"].isin(["N/A", "error-ja3"])]
    if df.empty:
        return pd.DataFrame()

    alertas = []

    for (src, dst, sni, ja3), grupo in df.groupby(["Origen", "Destino", "SNI", "JA3"]):
        if len(grupo) < min_paquetes:
            continue

        grupo = grupo.sort_values("Timestamp")
        deltas = grupo["Timestamp"].diff().dropna()
        if len(deltas) == 0:
            continue

        media = deltas.mean()
        if media <= 0:
            continue

        desviacion = deltas.std(ddof=0)
        cv = desviacion / media
        es_mecanico = cv < umbral_cv

        # Señales adicionales independientes del patrón temporal
        hit_ti = threat_intel.verificar_ip(dst) or threat_intel.verificar_dominio(sni)
        hit_dga = tls_analysis.es_posible_dga(sni)
        ja3_conocido = tls_analysis.identificar_ja3(ja3)

        if not (es_mecanico or hit_ti or hit_dga):
            continue

        # Severidad combinada: TI confirmado > patrón + DGA > patrón solo > DGA solo
        if hit_ti:
            severidad = "Crítica"
        elif es_mecanico and hit_dga:
            severidad = "Alta"
        elif es_mecanico:
            severidad = "Media"
        else:
            severidad = "Baja"

        razones = []
        if es_mecanico:
            razones.append(f"patrón mecánico (CV={cv:.3f})")
        if hit_ti:
            razones.append(f"destino en TI ({hit_ti['fuente']})")
        if hit_dga:
            razones.append(f"posible DGA (entropía={hit_dga['entropia']})")
        if ja3_conocido:
            razones.append(f"JA3 conocido: {ja3_conocido}")

        alertas.append({
            "IP Local": src,
            "Destino (SNI)": sni,
            "IP Destino": dst,
            "Huella JA3": ja3,
            "JA3 identificado": ja3_conocido or "",
            "Paquetes": len(grupo),
            "Intervalo medio (s)": round(media, 2),
            "CV": round(cv, 4),
            "Severidad": severidad,
            "Razones": "; ".join(razones),
        })

    if not alertas:
        return pd.DataFrame()

    orden_severidad = {"Crítica": 0, "Alta": 1, "Media": 2, "Baja": 3}
    df_alertas = pd.DataFrame(alertas)
    df_alertas["_orden"] = df_alertas["Severidad"].map(orden_severidad)
    return df_alertas.sort_values("_orden").drop(columns="_orden").reset_index(drop=True)
