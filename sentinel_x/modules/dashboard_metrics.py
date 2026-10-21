"""Métricas explicables para el centro de operaciones SOC."""

import pandas as pd

_PESOS = {"Crítica": 4, "Alta": 3, "Media": 2, "Baja": 1}


def riesgo_global(incidentes: list[dict], postura: pd.DataFrame) -> dict:
    """Resume riesgo operativo sin ocultar las señales que lo componen."""
    peso_incidentes = sum(_PESOS.get(i.get("severidad"), 1) for i in incidentes)
    peso_postura = 0
    if postura is not None and not postura.empty and "Severidad" in postura:
        peso_postura = sum(_PESOS.get(sev, 1) for sev in postura["Severidad"])
    puntuacion = min(100, peso_incidentes * 8 + peso_postura * 3)
    nivel = "Crítico" if puntuacion >= 70 else "Alto" if puntuacion >= 40 else "Moderado" if puntuacion >= 15 else "Bajo"
    return {"puntuacion": puntuacion, "nivel": nivel, "incidentes": len(incidentes),
            "hallazgos_postura": len(postura) if postura is not None else 0,
            "explicacion": f"{len(incidentes)} incidente(s) y {len(postura) if postura is not None else 0} hallazgo(s) de postura"}
