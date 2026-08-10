"""Logging centralizado para todo Sentinel-X."""

import logging
import os

_LOG_PATH = os.getenv("SENTINEL_LOG_PATH", "/home/claude/sentinel_x/data/sentinel_x.log")

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
