"""Logging centralizado para todo Sentinel-X."""

import logging
import os

# Ruta relativa al directorio de ejecución (igual que la base de datos), portable entre equipos.
_LOG_PATH = os.getenv("SENTINEL_LOG_PATH", "data/sentinel_x.log")

if os.path.dirname(_LOG_PATH):
    os.makedirs(os.path.dirname(_LOG_PATH), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(_LOG_PATH, encoding="utf-8"),
    ],
)


def get_logger(nombre: str) -> logging.Logger:
    return logging.getLogger(f"sentinel_x.{nombre}")
