"""Configuración común: rutas aisladas y el paquete en sys.path."""

import os
import sys
import tempfile

_TMP = tempfile.mkdtemp(prefix="sentinel_x_tests_")
os.environ.setdefault("SENTINEL_DB_PATH", os.path.join(_TMP, "test.db"))
os.environ.setdefault("SENTINEL_LOG_PATH", os.path.join(_TMP, "test.log"))
os.environ.setdefault("SENTINEL_TI_ENABLED", "false")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from core import database  # noqa: E402


@pytest.fixture()
def db():
    """Base de datos vacía para cada prueba."""
    database.inicializar_db()
    for tabla in ("casos_historial", "casos", "nist_autoevaluacion", "inventario_red",
                  "flujos_tls", "alertas_ids", "incidentes", "ti_hits", "redes_wifi",
                  "vulnerabilidades", "cve_cache", "ml_features"):
        database.ejecutar(f"DELETE FROM {tabla}")
    return database
