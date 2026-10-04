"""
Genera una base de datos SQLite de personas FICTICIAS de Latinoamérica para
probar el módulo de control de acceso / seguridad de lugares privados.

Principios de protección de datos aplicados (comunes a la normativa
latinoamericana: Ley 1581 CO, LGPD BR, LFPDPPP MX, Ley 25.326 AR, etc.):

- Datos 100% sintéticos: ninguna fila corresponde a una persona real y cada
  registro lleva es_sintetico = 1.
- Minimización: solo se guardan los datos necesarios para controlar acceso
  (sin biometría, sin dirección de domicilio, sin datos sensibles).
- Documentos con prefijo "DEMO-", correos en el dominio reservado
  example.com (RFC 2606) y teléfonos con un número nacional que empieza en
  0, que no es asignable: nada de esto puede contactar a nadie.
- Finalidad, consentimiento y fecha de expiración (retención) explícitos
  por registro.

Uso (desde sentinel_x/):
    python -m datos_demo.generar_personas --cantidad 200 --semilla 42
    python -m datos_demo.generar_personas --csv data/personas_demo.csv
"""

import argparse
import csv
import os
import random
import sqlite3
import unicodedata
from datetime import datetime, timedelta

from datos_demo.catalogos import FINALIDAD_TRATAMIENTO, PAISES, ROLES, ZONAS

RUTA_DB_DEFAULT = os.getenv("SENTINEL_DEMO_DB_PATH", "data/personas_demo.db")

ESQUEMA = """
CREATE TABLE IF NOT EXISTS personas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombres TEXT NOT NULL,
    apellidos TEXT NOT NULL,
    codigo_pais TEXT NOT NULL,
    pais TEXT NOT NULL,
    ciudad TEXT,
    tipo_documento TEXT NOT NULL,
    documento_ficticio TEXT NOT NULL UNIQUE,
    anio_nacimiento INTEGER,
    email TEXT,
    telefono TEXT,
    rol TEXT NOT NULL,
    nivel_acceso INTEGER NOT NULL,
    estado TEXT NOT NULL,
    consentimiento INTEGER NOT NULL,
    fecha_consentimiento TEXT,
    finalidad TEXT NOT NULL,
    norma_aplicable TEXT NOT NULL,
    fecha_registro TEXT NOT NULL,
    fecha_expiracion TEXT NOT NULL,
    es_sintetico INTEGER NOT NULL DEFAULT 1 CHECK (es_sintetico = 1)
);
CREATE INDEX IF NOT EXISTS idx_personas_rol ON personas(rol);
CREATE INDEX IF NOT EXISTS idx_personas_pais ON personas(codigo_pais);

CREATE TABLE IF NOT EXISTS zonas (
    nombre TEXT PRIMARY KEY,
    nivel_minimo INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS registros_acceso (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    persona_id INTEGER NOT NULL REFERENCES personas(id),
    zona TEXT NOT NULL REFERENCES zonas(nombre),
    fecha_hora TEXT NOT NULL,
    tipo_evento TEXT NOT NULL,        -- entrada / salida
    resultado TEXT NOT NULL,          -- permitido / denegado
    motivo TEXT
);
CREATE INDEX IF NOT EXISTS idx_accesos_fecha ON registros_acceso(fecha_hora);
CREATE INDEX IF NOT EXISTS idx_accesos_persona ON registros_acceso(persona_id);
"""


def _sin_tildes(texto: str) -> str:
    normalizado = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in normalizado if not unicodedata.combining(c))


def _generar_persona(rng: random.Random, ahora: datetime, usados: set) -> dict:
    codigo = rng.choice(list(PAISES))
    datos = PAISES[codigo]

    lista_nombres = datos["nombres_f"] if rng.random() < 0.5 else datos["nombres_m"]
    nombres = rng.choice(lista_nombres)
    apellidos = " ".join(rng.sample(datos["apellidos"], 2))

    rol = rng.choices(list(ROLES), weights=[r["peso"] for r in ROLES.values()])[0]
    cfg_rol = ROLES[rol]

    # Documento: prefijo DEMO- + dígitos, sin formato oficial ni verificador.
    while True:
        documento = f"DEMO-{codigo}-{rng.randint(0, 99_999_999):08d}"
        if documento not in usados:
            usados.add(documento)
            break

    usuario = _sin_tildes(f"{nombres.split()[0]}.{apellidos.split()[0]}").lower()
    email = f"{usuario}{rng.randint(1, 999)}@example.com"
    telefono = f"{datos['prefijo_tel']} 0{rng.randint(10_000_000, 99_999_999)}"

    fecha_registro = ahora - timedelta(days=rng.randint(0, 180))
    fecha_expiracion = fecha_registro + timedelta(days=cfg_rol["vigencia_dias"])
    consentimiento = 1 if rng.random() < 0.97 else 0

    if not consentimiento:
        estado = "pendiente_consentimiento"
    elif fecha_expiracion < ahora:
        estado = "expirado"
    elif rng.random() < 0.04:
        estado = "bloqueado"
    else:
        estado = "activo"

    return {
        "nombres": nombres,
        "apellidos": apellidos,
        "codigo_pais": codigo,
        "pais": datos["pais"],
        "ciudad": rng.choice(datos["ciudades"]),
        "tipo_documento": datos["tipo_documento"],
        "documento_ficticio": documento,
        "anio_nacimiento": rng.randint(ahora.year - 70, ahora.year - 18),
        "email": email,
        "telefono": telefono,
        "rol": rol,
        "nivel_acceso": rng.randint(*cfg_rol["nivel_acceso"]),
        "estado": estado,
        "consentimiento": consentimiento,
        "fecha_consentimiento": fecha_registro.isoformat(timespec="seconds") if consentimiento else None,
        "finalidad": FINALIDAD_TRATAMIENTO,
        "norma_aplicable": datos["norma"],
        "fecha_registro": fecha_registro.isoformat(timespec="seconds"),
        "fecha_expiracion": fecha_expiracion.isoformat(timespec="seconds"),
        "es_sintetico": 1,
    }


def _generar_accesos(rng: random.Random, personas: list[dict], ahora: datetime, dias: int) -> list[tuple]:
    """Simula eventos de entrada/salida aplicando las reglas de nivel y estado."""
    eventos = []
    for persona in personas:
        for _ in range(rng.randint(0, 6)):
            zona = rng.choice(list(ZONAS))
            momento = ahora - timedelta(days=rng.randint(0, dias), minutes=rng.randint(0, 1439))

            if persona["estado"] != "activo":
                resultado, motivo = "denegado", f"Persona en estado '{persona['estado']}'"
            elif persona["nivel_acceso"] < ZONAS[zona]:
                resultado, motivo = "denegado", f"Nivel {persona['nivel_acceso']} < requerido {ZONAS[zona]}"
            else:
                resultado, motivo = "permitido", None

            eventos.append((persona["id"], zona, momento.isoformat(timespec="seconds"),
                            "entrada", resultado, motivo))
            if resultado == "permitido":
                salida = momento + timedelta(minutes=rng.randint(5, 540))
                eventos.append((persona["id"], zona, salida.isoformat(timespec="seconds"),
                                "salida", "permitido", None))
    eventos.sort(key=lambda e: e[2])
    return eventos


def generar(cantidad: int, ruta_db: str, semilla: int | None, dias_accesos: int,
            ruta_csv: str | None = None) -> None:
    rng = random.Random(semilla)
    ahora = datetime.now().replace(microsecond=0)

    directorio = os.path.dirname(ruta_db)
    if directorio:
        os.makedirs(directorio, exist_ok=True)
    if os.path.exists(ruta_db):
        os.remove(ruta_db)

    conn = sqlite3.connect(ruta_db)
    try:
        conn.executescript(ESQUEMA)
        conn.executemany("INSERT INTO zonas (nombre, nivel_minimo) VALUES (?, ?)", ZONAS.items())

        usados: set = set()
        personas = [_generar_persona(rng, ahora, usados) for _ in range(cantidad)]
        columnas = list(personas[0].keys()) if personas else []
        sql = (f"INSERT INTO personas ({', '.join(columnas)}) "
               f"VALUES ({', '.join('?' for _ in columnas)})")
        for persona in personas:
            persona["id"] = conn.execute(sql, [persona[c] for c in columnas]).lastrowid

        eventos = _generar_accesos(rng, personas, ahora, dias_accesos)
        conn.executemany(
            "INSERT INTO registros_acceso (persona_id, zona, fecha_hora, tipo_evento, resultado, motivo) "
            "VALUES (?, ?, ?, ?, ?, ?)", eventos)
        conn.commit()
    finally:
        conn.close()

    if ruta_csv and personas:
        directorio_csv = os.path.dirname(ruta_csv)
        if directorio_csv:
            os.makedirs(directorio_csv, exist_ok=True)
        with open(ruta_csv, "w", newline="", encoding="utf-8") as f:
            escritor = csv.DictWriter(f, fieldnames=["id"] + columnas)
            escritor.writeheader()
            escritor.writerows(personas)

    print(f"Base de datos sintética creada en {ruta_db}: "
          f"{len(personas)} personas, {len(eventos)} registros de acceso.")
    if ruta_csv:
        print(f"CSV exportado en {ruta_csv}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera personas ficticias latinoamericanas para pruebas.")
    parser.add_argument("--cantidad", type=int, default=200, help="Número de personas (default 200)")
    parser.add_argument("--db", default=RUTA_DB_DEFAULT, help=f"Ruta SQLite (default {RUTA_DB_DEFAULT})")
    parser.add_argument("--semilla", type=int, default=None, help="Semilla para resultados reproducibles")
    parser.add_argument("--dias-accesos", type=int, default=30, help="Días de historial de accesos (default 30)")
    parser.add_argument("--csv", default=None, help="Exporta además la tabla de personas a CSV")
    args = parser.parse_args()
    if args.cantidad < 0:
        parser.error("--cantidad debe ser >= 0")
    generar(args.cantidad, args.db, args.semilla, args.dias_accesos, args.csv)


if __name__ == "__main__":
    main()
