"""
Persistencia SQLite para Sentinel-X.

Todas las escrituras pasan por una única conexión protegida por lock,
porque SQLite serializa escritores y los hilos de captura escriben
concurrentemente. Se usa WAL para no bloquear lecturas del dashboard
mientras un hilo escribe.
"""

import os
import re
import sqlite3
import threading
import time

from core.config import CONFIG
from core.logger import get_logger

logger = get_logger("database")

_lock_db = threading.Lock()
_conn: sqlite3.Connection | None = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        directorio_db = os.path.dirname(CONFIG["db_path"])
        if directorio_db:
            os.makedirs(directorio_db, exist_ok=True)
        _conn = sqlite3.connect(CONFIG["db_path"], check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL;")
        _conn.execute("PRAGMA synchronous=NORMAL;")
    return _conn


def _migrar(conn: sqlite3.Connection) -> None:
    """Añade columnas nuevas a bases creadas por versiones anteriores."""
    columnas = {fila[1] for fila in conn.execute("PRAGMA table_info(inventario_red)")}
    if "servicios_detalle" not in columnas:
        conn.execute("ALTER TABLE inventario_red ADD COLUMN servicios_detalle TEXT")


def inicializar_db() -> None:
    """Crea las tablas si no existen. Llamar una vez al arranque."""
    with _lock_db:
        conn = _get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS flujos_tls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                origen TEXT, destino TEXT, puerto INTEGER,
                sni TEXT, ja3 TEXT, ja3_conocido TEXT,
                tamano_bytes INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_flujos_ts ON flujos_tls(timestamp);
            CREATE INDEX IF NOT EXISTS idx_flujos_destino ON flujos_tls(destino);

            CREATE TABLE IF NOT EXISTS alertas_ids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                fecha_hora TEXT, ip_origen TEXT, ip_destino TEXT,
                gravedad INTEGER, categoria TEXT, firma TEXT,
                mitre_tactica TEXT, mitre_tecnica TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_alertas_ts ON alertas_ids(timestamp);

            CREATE TABLE IF NOT EXISTS incidentes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                tipo TEXT, severidad TEXT, ip_principal TEXT,
                descripcion TEXT, mitre_tecnicas TEXT, fuentes TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_incidentes_ts ON incidentes(timestamp);

            CREATE TABLE IF NOT EXISTS inventario_red (
                ip TEXT PRIMARY KEY,
                mac TEXT, fabricante TEXT, tipo TEXT,
                hostname TEXT, fuente_hostname TEXT,
                os_detectado TEXT, puertos_abiertos TEXT, servicios TEXT,
                servicios_detalle TEXT,
                primera_vez REAL, ultima_vez REAL
            );

            CREATE TABLE IF NOT EXISTS ti_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                indicador TEXT, tipo_indicador TEXT,
                fuente TEXT, contexto TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ti_ts ON ti_hits(timestamp);

            CREATE TABLE IF NOT EXISTS redes_wifi (
                bssid TEXT PRIMARY KEY,
                ssid TEXT, cifrado TEXT, pmf TEXT,
                akm_suites TEXT, cipher_suites TEXT,
                primera_vez REAL, ultima_vez REAL
            );

            -- Casos de respuesta a incidentes (NIST SP 800-61 / CSF 2.0 RS-RC).
            -- No se rotan por antigüedad: son el registro de lo que se investigó.
            CREATE TABLE IF NOT EXISTS casos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                creado REAL NOT NULL, actualizado REAL NOT NULL,
                ip TEXT, titulo TEXT, severidad TEXT, prioridad TEXT,
                estado TEXT, fuentes TEXT, mitre TEXT, resumen TEXT, responsable TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_casos_estado ON casos(estado);

            CREATE TABLE IF NOT EXISTS casos_historial (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                caso_id INTEGER NOT NULL REFERENCES casos(id),
                timestamp REAL NOT NULL,
                estado TEXT, nota TEXT, autor TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_historial_caso ON casos_historial(caso_id);

            -- CVE asociados a los servicios del inventario (NVD + CISA KEV).
            CREATE TABLE IF NOT EXISTS vulnerabilidades (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                ip TEXT, puerto INTEGER, servicio TEXT, cpe TEXT,
                cve TEXT, cvss REAL, severidad TEXT, kev INTEGER, descripcion TEXT,
                UNIQUE(ip, puerto, cve)
            );
            CREATE INDEX IF NOT EXISTS idx_vulns_ip ON vulnerabilidades(ip);

            -- Respuestas del NVD por CPE (también vacías) para respetar su límite de peticiones.
            CREATE TABLE IF NOT EXISTS cve_cache (
                cpe TEXT PRIMARY KEY,
                timestamp REAL NOT NULL,
                respuesta TEXT
            );

            -- Features por host y minuto: la memoria del baseline ML entre reinicios.
            CREATE TABLE IF NOT EXISTS ml_features (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                host TEXT NOT NULL, minuto INTEGER NOT NULL,
                bytes_totales REAL, paquetes REAL, destinos_unicos REAL, puertos_unicos REAL,
                UNIQUE(host, minuto)
            );
            CREATE INDEX IF NOT EXISTS idx_ml_ts ON ml_features(timestamp);

            -- Lo que cada dispositivo anuncia de sí mismo (DHCP, mDNS, SSDP).
            -- clave = MAC, o "ip:<ip>" para fuentes que solo ven la IP.
            CREATE TABLE IF NOT EXISTS identidad_obs (
                clave TEXT NOT NULL, fuente TEXT NOT NULL,
                mac TEXT, ip TEXT, datos TEXT, timestamp REAL,
                PRIMARY KEY (clave, fuente)
            );

            -- Nombres y tipos asignados a mano: el inventario como registro de activos.
            CREATE TABLE IF NOT EXISTS etiquetas_dispositivo (
                mac TEXT PRIMARY KEY,
                etiqueta TEXT, tipo TEXT, notas TEXT, actualizado REAL
            );

            -- Autoevaluación de subcategorías NIST CSF que la red no puede medir.
            CREATE TABLE IF NOT EXISTS nist_autoevaluacion (
                subcategoria TEXT PRIMARY KEY,
                estado TEXT, nota TEXT, actualizado REAL
            );
        """)
        _migrar(conn)
        conn.commit()
    logger.info("Base de datos inicializada en %s", CONFIG["db_path"])


_TABLAS_ROTABLES = ("flujos_tls", "alertas_ids", "incidentes", "ti_hits", "ml_features")
_TABLAS_INSERTABLES = set(_TABLAS_ROTABLES) | {"casos", "casos_historial"}
_RE_COLUMNA = re.compile(r"^[a-z_][a-z0-9_]*$")


def insertar(tabla: str, registro: dict) -> int | None:
    """Inserta un registro en la tabla dada. Thread-safe. Devuelve el id insertado."""
    if not registro:
        return None
    if tabla not in _TABLAS_INSERTABLES:
        raise ValueError(f"Tabla no permitida: {tabla}")
    # Las columnas se interpolan en el SQL: solo se aceptan identificadores simples.
    if not all(_RE_COLUMNA.match(c) for c in registro):
        raise ValueError(f"Nombre de columna no válido en {tabla}")
    columnas = ", ".join(registro.keys())
    placeholders = ", ".join("?" for _ in registro)
    sql = f"INSERT INTO {tabla} ({columnas}) VALUES ({placeholders})"
    with _lock_db:
        try:
            conn = _get_conn()
            cursor = conn.execute(sql, list(registro.values()))
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as exc:
            logger.error("Error insertando en %s: %s", tabla, exc)
            return None


def ejecutar(sql: str, params: tuple = ()) -> int:
    """Ejecuta un UPDATE/DELETE parametrizado. Devuelve filas afectadas."""
    with _lock_db:
        try:
            conn = _get_conn()
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor.rowcount
        except sqlite3.Error as exc:
            logger.error("Error ejecutando sentencia: %s", exc)
            return 0


def ejecutar_varios(sql: str, filas: list[tuple]) -> None:
    """executemany en una sola transacción (inserciones en lote)."""
    if not filas:
        return
    with _lock_db:
        try:
            conn = _get_conn()
            conn.executemany(sql, filas)
            conn.commit()
        except sqlite3.Error as exc:
            logger.error("Error en inserción en lote: %s", exc)


def upsert_red_wifi(red: dict) -> None:
    """Guarda el último estado de seguridad observado para un BSSID."""
    ahora = time.time()
    with _lock_db:
        try:
            conn = _get_conn()
            conn.execute("""
                INSERT INTO redes_wifi
                    (bssid, ssid, cifrado, pmf, akm_suites, cipher_suites, primera_vez, ultima_vez)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bssid) DO UPDATE SET
                    ssid=excluded.ssid, cifrado=excluded.cifrado, pmf=excluded.pmf,
                    akm_suites=excluded.akm_suites, cipher_suites=excluded.cipher_suites,
                    ultima_vez=excluded.ultima_vez
            """, (
                red["bssid"], red.get("ssid", ""), red.get("cifrado", ""), red.get("pmf", ""),
                ", ".join(red.get("akm_suites", [])), ", ".join(red.get("cipher_suites", [])),
                ahora, ahora,
            ))
            conn.commit()
        except sqlite3.Error as exc:
            logger.error("Error guardando red Wi-Fi: %s", exc)


def upsert_inventario(perfil: dict) -> None:
    """Inserta o actualiza un dispositivo en el inventario, preservando 'primera_vez'."""
    ahora = time.time()
    with _lock_db:
        try:
            conn = _get_conn()
            existente = conn.execute(
                "SELECT primera_vez FROM inventario_red WHERE ip = ?", (perfil["ip"],)
            ).fetchone()
            primera_vez = existente[0] if existente else ahora

            conn.execute("""
                INSERT INTO inventario_red
                    (ip, mac, fabricante, tipo, hostname, fuente_hostname,
                     os_detectado, puertos_abiertos, servicios, servicios_detalle,
                     primera_vez, ultima_vez)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac=excluded.mac, fabricante=excluded.fabricante, tipo=excluded.tipo,
                    hostname=excluded.hostname, fuente_hostname=excluded.fuente_hostname,
                    -- Un re-escaneo sin Nmap no borra lo que Nmap ya averiguó.
                    os_detectado=COALESCE(excluded.os_detectado, inventario_red.os_detectado),
                    puertos_abiertos=COALESCE(excluded.puertos_abiertos, inventario_red.puertos_abiertos),
                    servicios=COALESCE(excluded.servicios, inventario_red.servicios),
                    servicios_detalle=COALESCE(excluded.servicios_detalle, inventario_red.servicios_detalle),
                    ultima_vez=excluded.ultima_vez
            """, (
                perfil["ip"], perfil.get("mac"), perfil.get("fabricante"),
                perfil.get("tipo"), perfil.get("hostname"), perfil.get("fuente_hostname"),
                perfil.get("os_detectado"), perfil.get("puertos_abiertos"),
                perfil.get("servicios"), perfil.get("servicios_detalle"), primera_vez, ahora,
            ))
            conn.commit()
        except sqlite3.Error as exc:
            logger.error("Error en upsert_inventario: %s", exc)


def consultar(sql: str, params: tuple = ()) -> list[dict]:
    """Ejecuta un SELECT y devuelve lista de dicts."""
    with _lock_db:
        try:
            conn = _get_conn()
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(sql, params)
            filas = [dict(r) for r in cursor.fetchall()]
            conn.row_factory = None
            return filas
        except sqlite3.Error as exc:
            logger.error("Error en consulta: %s", exc)
            return []


def rotar_si_excede_limite() -> None:
    """
    Borra registros más viejos que la retención configurada. Si además el
    archivo supera el tamaño máximo, recorta la mitad más antigua de cada
    tabla de eventos. Los casos de respuesta a incidentes nunca se rotan.
    """
    limite_ts = time.time() - CONFIG["db_retencion_dias"] * 86400

    tamano_mb = 0.0
    if os.path.exists(CONFIG["db_path"]):
        tamano_mb = os.path.getsize(CONFIG["db_path"]) / (1024 * 1024)
    excede_tamano = tamano_mb >= CONFIG["db_max_tamano_mb"]

    with _lock_db:
        try:
            conn = _get_conn()
            for tabla in _TABLAS_ROTABLES:
                conn.execute(f"DELETE FROM {tabla} WHERE timestamp < ?", (limite_ts,))
                if excede_tamano:
                    conn.execute(f"""
                        DELETE FROM {tabla} WHERE id IN (
                            SELECT id FROM {tabla} ORDER BY timestamp ASC
                            LIMIT (SELECT COUNT(*) / 2 FROM {tabla})
                        )
                    """)
            # VACUUM no puede ejecutarse dentro de una transacción abierta.
            conn.commit()
            conn.execute("VACUUM;")
            logger.info("Rotación de DB completada (retención: %d días, tamaño previo: %.1f MB%s)",
                        CONFIG["db_retencion_dias"], tamano_mb,
                        ", recorte por tamaño" if excede_tamano else "")
        except sqlite3.Error as exc:
            logger.error("Error rotando DB: %s", exc)
