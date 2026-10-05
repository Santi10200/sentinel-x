"""
Gestión de casos de respuesta a incidentes según NIST SP 800-61.

El motor de correlación produce "incidentes" efímeros (se recalculan con
cada análisis). Un caso es la decisión humana de investigarlo: se declara
(DE.AE-08), se triagea y prioriza (RS.MA-02/03), se analiza (RS.AN-03),
se contiene y erradica (RS.MI-01/02), se recupera (RC.RP-01) y se cierra
con lecciones aprendidas (ID.IM-03).

Cada cambio de estado o nota queda en `casos_historial` con marca de
tiempo y autor: es el registro de acciones que pide RS.AN-06. El
historial es solo-anexar; nunca se edita ni se borra desde la UI.
"""

import json
import time

from core import database
from core.logger import get_logger

logger = get_logger("respuesta_incidentes")

# Fases del ciclo de vida (SP 800-61) con la función/subcategoría CSF 2.0 que cubren.
ESTADOS: list[tuple[str, str, str]] = [
    ("Detectado", "DE.AE-08", "Incidente declarado a partir de eventos correlacionados."),
    ("En análisis", "RS.MA-02 · RS.AN-03", "Triaje, validación y análisis de causa raíz."),
    ("Contenido", "RS.MI-01", "Se limitó la propagación (aislar host, bloquear IP/dominio)."),
    ("Erradicado", "RS.MI-02", "Se eliminó la causa (malware, cuenta comprometida, servicio)."),
    ("Recuperado", "RC.RP-01", "Servicios restaurados y verificados."),
    ("Cerrado", "ID.IM-03", "Lecciones aprendidas documentadas."),
]
NOMBRES_ESTADO = [e[0] for e in ESTADOS]
ESTADOS_ABIERTOS = NOMBRES_ESTADO[:-1]

# Prioridad a partir de la severidad combinada del motor de correlación.
PRIORIDAD_POR_SEVERIDAD = {
    "Crítica": "P1 · respuesta inmediata",
    "Alta": "P2 · mismo día",
    "Media": "P3 · esta semana",
    "Baja": "P4 · planificada",
}

# Acciones sugeridas por fuente de detección (guía para estudiantes/pymes).
PLAYBOOK: dict[str, list[str]] = {
    "Beaconing C2": [
        "Aislar el host local de la red (VLAN de cuarentena o desconectar).",
        "Bloquear el dominio/IP de destino en DNS y firewall perimetral.",
        "Revisar procesos con conexiones salientes persistentes (netstat/ss, EDR).",
        "Buscar el mismo JA3/SNI en otros hosts del inventario.",
    ],
    "Movimiento lateral (fan-out)": [
        "Identificar el proceso/usuario que generó el barrido en el host origen.",
        "Verificar si es un escáner autorizado (inventario, Nmap del equipo de TI).",
        "Si no es autorizado: aislar el host y rotar credenciales usadas en él.",
    ],
    "Movimiento lateral (puerto sensible)": [
        "Validar que el origen esté autorizado a administrar el destino.",
        "Revisar logs de autenticación del destino (Windows 4624/4625, auth.log).",
        "Restringir SMB/RDP/WinRM/SSH a hosts de administración (PR.IR-01).",
    ],
    "Baseline ML": [
        "Comparar la ventana anómala con la actividad legítima (backups, actualizaciones).",
        "Si no hay explicación, correlacionar con alertas IDS y TLS del mismo host.",
    ],
    "Suricata IDS": [
        "Revisar la firma y el payload en eve.json para descartar falso positivo.",
        "Si es válido, contener el host y buscar la técnica MITRE asociada en otros activos.",
    ],
}


def _ahora() -> float:
    return time.time()


def registrar_evento(caso_id: int, estado: str, nota: str, autor: str = "analista") -> None:
    database.insertar("casos_historial", {
        "caso_id": caso_id, "timestamp": _ahora(),
        "estado": estado, "nota": nota, "autor": autor or "analista",
    })


def caso_abierto_para_ip(ip: str) -> dict | None:
    filas = database.consultar(
        f"SELECT * FROM casos WHERE ip = ? AND estado IN ({','.join('?' * len(ESTADOS_ABIERTOS))}) "
        "ORDER BY id DESC LIMIT 1",
        (ip, *ESTADOS_ABIERTOS),
    )
    return filas[0] if filas else None


def abrir_caso(incidente: dict, autor: str = "analista") -> tuple[int, bool]:
    """
    Declara un caso a partir de un incidente correlacionado. Si ya existe
    un caso abierto para la misma IP lo reutiliza (no duplica).
    Devuelve (id, creado_nuevo).
    """
    ip = incidente["ip_principal"]
    existente = caso_abierto_para_ip(ip)
    if existente:
        return existente["id"], False

    ahora = _ahora()
    severidad = incidente.get("severidad", "Media")
    resumen = " | ".join(h["descripcion"] for h in incidente.get("hallazgos", [])[:5])
    caso_id = database.insertar("casos", {
        "creado": ahora, "actualizado": ahora, "ip": ip,
        "titulo": f"{severidad}: actividad sospechosa en {ip}",
        "severidad": severidad,
        "prioridad": PRIORIDAD_POR_SEVERIDAD.get(severidad, "P3 · esta semana"),
        "estado": "Detectado",
        "fuentes": json.dumps(incidente.get("fuentes", []), ensure_ascii=False),
        "mitre": json.dumps(incidente.get("mitre_tecnicas", []), ensure_ascii=False),
        "resumen": resumen, "responsable": autor,
    })
    if caso_id is None:
        raise RuntimeError("No se pudo crear el caso en la base de datos.")
    registrar_evento(caso_id, "Detectado", f"Caso declarado. Fuentes: {', '.join(incidente.get('fuentes', []))}", autor)
    logger.info("Caso #%s abierto para %s (%s).", caso_id, ip, severidad)
    return caso_id, True


def cambiar_estado(caso_id: int, nuevo_estado: str, nota: str, autor: str = "analista") -> None:
    if nuevo_estado not in NOMBRES_ESTADO:
        raise ValueError(f"Estado no válido: {nuevo_estado}")
    database.ejecutar(
        "UPDATE casos SET estado = ?, actualizado = ? WHERE id = ?",
        (nuevo_estado, _ahora(), caso_id),
    )
    registrar_evento(caso_id, nuevo_estado, nota or f"Cambio de estado a {nuevo_estado}.", autor)


def agregar_nota(caso_id: int, nota: str, autor: str = "analista") -> None:
    caso = obtener_caso(caso_id)
    if not caso or not nota.strip():
        return
    database.ejecutar("UPDATE casos SET actualizado = ? WHERE id = ?", (_ahora(), caso_id))
    registrar_evento(caso_id, caso["estado"], nota.strip(), autor)


def obtener_caso(caso_id: int) -> dict | None:
    filas = database.consultar("SELECT * FROM casos WHERE id = ?", (caso_id,))
    return _decodificar(filas[0]) if filas else None


def listar_casos(solo_abiertos: bool = False) -> list[dict]:
    if solo_abiertos:
        filas = database.consultar(
            f"SELECT * FROM casos WHERE estado IN ({','.join('?' * len(ESTADOS_ABIERTOS))}) ORDER BY id DESC",
            tuple(ESTADOS_ABIERTOS),
        )
    else:
        filas = database.consultar("SELECT * FROM casos ORDER BY id DESC")
    return [_decodificar(f) for f in filas]


def historial(caso_id: int) -> list[dict]:
    return database.consultar(
        "SELECT * FROM casos_historial WHERE caso_id = ? ORDER BY timestamp ASC, id ASC", (caso_id,)
    )


def acciones_sugeridas(fuentes: list[str]) -> list[str]:
    acciones: list[str] = []
    for fuente in fuentes:
        for accion in PLAYBOOK.get(fuente, []):
            if accion not in acciones:
                acciones.append(accion)
    return acciones


def _decodificar(fila: dict) -> dict:
    fila = dict(fila)
    for campo in ("fuentes", "mitre"):
        try:
            fila[campo] = json.loads(fila.get(campo) or "[]")
        except (TypeError, json.JSONDecodeError):
            fila[campo] = []
    return fila
