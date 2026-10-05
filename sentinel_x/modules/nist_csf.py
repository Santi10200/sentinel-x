"""
Evaluación orientada a NIST Cybersecurity Framework (CSF) 2.0.

CSF 2.0 organiza los resultados de ciberseguridad en 6 funciones:
GOVERN (GV), IDENTIFY (ID), PROTECT (PR), DETECT (DE), RESPOND (RS) y
RECOVER (RC). Cada función tiene categorías y subcategorías (ej.
DE.CM-01: "Networks and network services are monitored to find
potentially adverse events").

Este módulo NO certifica cumplimiento. Mide, con la evidencia que una
herramienta de red puede observar, qué subcategorías están cubiertas y
cuáles no, y deja el resto (gobierno, formación, copias de seguridad)
como autoevaluación manual. El resultado es un "perfil actual" en el
sentido del CSF: una foto para priorizar mejoras, no una auditoría.

La función `evaluar(contexto)` es pura (no lee estado global) para que
se pueda probar y reutilizar en el informe.
"""

import time
from dataclasses import dataclass, field

import pandas as pd

FUNCIONES = {
    "GV": "Gobernar (Govern)",
    "ID": "Identificar (Identify)",
    "PR": "Proteger (Protect)",
    "DE": "Detectar (Detect)",
    "RS": "Responder (Respond)",
    "RC": "Recuperar (Recover)",
}

CUMPLE, PARCIAL, NO_CUMPLE, SIN_DATOS = "Cumple", "Parcial", "No cumple", "Sin datos"
_PUNTOS = {CUMPLE: 1.0, PARCIAL: 0.5, NO_CUMPLE: 0.0}
ESTADOS_MANUALES = [NO_CUMPLE, PARCIAL, CUMPLE]

# Subcategorías CSF 2.0 con texto resumido en español.
SUBCATEGORIAS: dict[str, str] = {
    "GV.OC-03": "Se conocen y gestionan los requisitos legales, regulatorios y contractuales de ciberseguridad.",
    "GV.PO-01": "Existe una política de gestión de riesgos de ciberseguridad comunicada y aplicada.",
    "GV.RR-02": "Roles y responsabilidades de ciberseguridad están definidos y asignados.",
    "ID.AM-01": "Se mantiene el inventario del hardware de la organización.",
    "ID.AM-02": "Se mantiene el inventario de software, servicios y sistemas.",
    "ID.AM-03": "Se mantienen representaciones de los flujos de comunicación de red autorizados.",
    "ID.RA-01": "Se identifican, validan y registran las vulnerabilidades de los activos.",
    "ID.RA-02": "Se recibe inteligencia de amenazas de fuentes externas.",
    "ID.RA-03": "Se identifican y registran amenazas internas y externas.",
    "ID.RA-05": "Amenazas, vulnerabilidades e impacto se usan para priorizar la respuesta al riesgo.",
    "PR.AT-01": "El personal recibe concienciación y formación en ciberseguridad.",
    "PR.DS-02": "Se protege la confidencialidad e integridad de los datos en tránsito.",
    "PR.DS-11": "Se hacen, protegen y prueban copias de seguridad.",
    "PR.PS-01": "Se aplican prácticas de gestión de configuración segura.",
    "PR.IR-01": "Redes y entornos están protegidos contra acceso y uso lógico no autorizado.",
    "DE.CM-01": "Se monitorizan las redes y servicios de red para encontrar eventos adversos.",
    "DE.AE-02": "Se analizan los eventos potencialmente adversos.",
    "DE.AE-03": "Se correlaciona información de múltiples fuentes.",
    "DE.AE-04": "Se estima el impacto y alcance de los eventos adversos.",
    "DE.AE-06": "La información de eventos adversos llega al personal y herramientas autorizadas.",
    "DE.AE-07": "La inteligencia de amenazas y el contexto se integran en el análisis.",
    "DE.AE-08": "Se declaran incidentes cuando los eventos cumplen los criterios definidos.",
    "RS.MA-02": "Los reportes de incidentes se triagean y validan.",
    "RS.MA-03": "Los incidentes se categorizan y priorizan.",
    "RS.AN-03": "Se analiza qué ocurrió durante el incidente y su causa raíz.",
    "RS.AN-06": "Las acciones de la investigación se registran preservando su integridad.",
    "RS.MI-01": "Los incidentes se contienen.",
    "RS.MI-02": "Los incidentes se erradican.",
    "RC.RP-01": "Se ejecuta la parte de recuperación del plan de respuesta.",
    "RC.CO-03": "Se comunican las actividades de recuperación a las partes interesadas.",
}

# Subcategorías que la red no puede observar: se evalúan por autoevaluación.
MANUALES: dict[str, str] = {
    "GV.OC-03": "Identifica normativas aplicables (protección de datos, sector) y quién responde por ellas.",
    "GV.PO-01": "Redacta una política breve: qué se protege, quién decide y cada cuánto se revisa.",
    "GV.RR-02": "Asigna un responsable de seguridad y un suplente, aunque sea a tiempo parcial.",
    "PR.AT-01": "Formación anual en phishing y contraseñas; registra quién la completó.",
    "PR.DS-11": "Copias 3-2-1 (una fuera de línea) y prueba de restauración al menos trimestral.",
    "RC.CO-03": "Define a quién se informa durante la recuperación y por qué canal.",
}


@dataclass
class Contexto:
    """Evidencia observable por Sentinel-X que alimenta la evaluación."""
    sensores: dict[str, bool] = field(default_factory=dict)
    inventario: list[dict] = field(default_factory=list)
    inventario_ultima_vez: float | None = None
    eventos_lan: int = 0
    flujos_tls: int = 0
    alertas_ids: int = 0
    ti_habilitado: bool = False
    ti_indicadores: int = 0
    mitre_tecnicas: int = 0
    analisis_ejecutado: bool = False
    incidentes: list[dict] = field(default_factory=list)
    postura: pd.DataFrame = field(default_factory=pd.DataFrame)
    redes_wifi: list[dict] = field(default_factory=list)
    casos: list[dict] = field(default_factory=list)
    autoevaluacion: dict[str, str] = field(default_factory=dict)
    ahora: float = field(default_factory=time.time)


def _fila(sub: str, estado: str, evidencia: str, recomendacion: str, tipo: str = "Automática") -> dict:
    return {
        "Función": FUNCIONES[sub[:2]],
        "Subcategoría": sub,
        "Resultado esperado": SUBCATEGORIAS[sub],
        "Estado": estado,
        "Evidencia": evidencia,
        "Recomendación": recomendacion if estado != CUMPLE else "",
        "Tipo": tipo,
    }


def _hallazgos(postura: pd.DataFrame, subcategoria: str) -> pd.DataFrame:
    if postura is None or postura.empty or "NIST CSF" not in postura.columns:
        return pd.DataFrame()
    return postura[postura["NIST CSF"].str.contains(subcategoria, regex=False, na=False)]


def _estado_por_hallazgos(df: pd.DataFrame) -> str:
    if df.empty:
        return CUMPLE
    if df["Severidad"].isin(["Crítica", "Alta"]).any():
        return NO_CUMPLE
    return PARCIAL


def _resumen_severidades(df: pd.DataFrame) -> str:
    conteo = df["Severidad"].value_counts()
    return ", ".join(f"{n} {sev.lower()}" for sev, n in conteo.items())


def evaluar(ctx: Contexto) -> pd.DataFrame:
    filas: list[dict] = []
    con_nmap = [h for h in ctx.inventario if h.get("puertos_abiertos") or h.get("servicios")]
    severos = [i for i in ctx.incidentes if i.get("severidad") in ("Crítica", "Alta")]
    ips_con_caso = {c.get("ip") for c in ctx.casos}

    # ── GOVERN / manuales ─────────────────────────────────────────────────
    for sub, guia in MANUALES.items():
        estado = ctx.autoevaluacion.get(sub, SIN_DATOS)
        filas.append(_fila(sub, estado, "Autoevaluación del responsable" if estado != SIN_DATOS
                           else "Pendiente de autoevaluación", guia, tipo="Manual"))

    # ── IDENTIFY ─────────────────────────────────────────────────────────
    if not ctx.inventario:
        filas.append(_fila("ID.AM-01", NO_CUMPLE, "Inventario vacío",
                           "Ejecuta un escaneo en la pestaña Dispositivos."))
    else:
        dias = (ctx.ahora - ctx.inventario_ultima_vez) / 86400 if ctx.inventario_ultima_vez else None
        reciente = dias is not None and dias <= 7
        filas.append(_fila(
            "ID.AM-01", CUMPLE if reciente else PARCIAL,
            f"{len(ctx.inventario)} dispositivos" + (f", último escaneo hace {dias:.1f} días" if dias is not None else ""),
            "Repite el escaneo al menos semanalmente para detectar equipos nuevos o no autorizados.",
        ))

    if not ctx.inventario:
        filas.append(_fila("ID.AM-02", SIN_DATOS, "Sin inventario", "Escanea con Nmap -sV activado."))
    else:
        proporcion = len(con_nmap) / len(ctx.inventario)
        estado = CUMPLE if proporcion >= 0.8 else PARCIAL if con_nmap else NO_CUMPLE
        filas.append(_fila(
            "ID.AM-02", estado, f"Servicios identificados en {len(con_nmap)}/{len(ctx.inventario)} hosts",
            "Activa 'Nmap -O -sV' en el escaneo para inventariar servicios y versiones.",
        ))

    if ctx.eventos_lan:
        filas.append(_fila("ID.AM-03", CUMPLE, f"{ctx.eventos_lan} eventos LAN para el mapa de flujos", ""))
    elif ctx.flujos_tls:
        filas.append(_fila("ID.AM-03", PARCIAL, "Solo flujos TLS salientes; sin tráfico interno",
                           "Verifica el sniffer LAN para mapear también el tráfico este-oeste."))
    else:
        filas.append(_fila("ID.AM-03", NO_CUMPLE, "Sin tráfico capturado",
                           "Ejecuta con sudo y comprueba la interfaz de captura."))

    vulns = _hallazgos(ctx.postura, "ID.RA-01")
    if not con_nmap:
        filas.append(_fila("ID.RA-01", SIN_DATOS, "Sin datos de servicios para evaluar vulnerabilidades",
                           "Escanea con Nmap para detectar servicios inseguros."))
    else:
        estado = _estado_por_hallazgos(vulns)
        filas.append(_fila(
            "ID.RA-01", estado,
            "Sin servicios inseguros detectados" if vulns.empty else f"{len(vulns)} servicios inseguros ({_resumen_severidades(vulns)})",
            "Corrige los servicios listados en 'Postura' empezando por los críticos.",
        ))

    if not ctx.ti_habilitado:
        filas.append(_fila("ID.RA-02", NO_CUMPLE, "Threat Intelligence deshabilitada",
                           "Activa SENTINEL_TI_ENABLED=true (feeds abuse.ch y CISA KEV)."))
    else:
        filas.append(_fila("ID.RA-02", CUMPLE if ctx.ti_indicadores else PARCIAL,
                           f"{ctx.ti_indicadores} indicadores cargados",
                           "Comprueba la conectividad a los feeds (pestaña ML / Zeek / TI)."))

    filas.append(_fila(
        "ID.RA-03", CUMPLE if ctx.mitre_tecnicas else PARCIAL,
        f"Índice MITRE ATT&CK con {ctx.mitre_tecnicas} técnicas" if ctx.mitre_tecnicas else "Índice MITRE no cargado",
        "Permite acceso a GitHub o usa el fallback offline de MITRE.",
    ))

    filas.append(_fila(
        "ID.RA-05", CUMPLE if ctx.analisis_ejecutado else NO_CUMPLE,
        "Incidentes priorizados por severidad combinada" if ctx.analisis_ejecutado else "Análisis no ejecutado",
        "Ejecuta el análisis (pestaña Resumen) para priorizar riesgos.",
    ))

    # ── PROTECT ──────────────────────────────────────────────────────────
    transito = _hallazgos(ctx.postura, "PR.DS-02")
    if not (ctx.eventos_lan or ctx.redes_wifi):
        filas.append(_fila("PR.DS-02", SIN_DATOS, "Sin tráfico LAN ni redes Wi-Fi observadas",
                           "Activa el sniffer LAN o la captura Wi-Fi para evaluar cifrado en tránsito."))
    else:
        filas.append(_fila(
            "PR.DS-02", _estado_por_hallazgos(transito),
            "No se observaron protocolos en claro ni Wi-Fi débil" if transito.empty
            else f"{len(transito)} hallazgos ({_resumen_severidades(transito)})",
            "Sustituye protocolos en claro (Telnet, FTP, POP3, HTTP) por variantes cifradas.",
        ))

    config = _hallazgos(ctx.postura, "PR.PS-01")
    if not con_nmap:
        filas.append(_fila("PR.PS-01", SIN_DATOS, "Sin datos de servicios", "Escanea con Nmap."))
    else:
        filas.append(_fila(
            "PR.PS-01", _estado_por_hallazgos(config),
            "Configuraciones de servicio sin hallazgos" if config.empty
            else f"{len(config)} servicios con configuración insegura",
            "Deshabilita servicios innecesarios y aplica una línea base (CIS Benchmarks).",
        ))

    acceso = _hallazgos(ctx.postura, "PR.IR-01")
    if not ctx.redes_wifi:
        filas.append(_fila("PR.IR-01", SIN_DATOS, "Sin redes Wi-Fi observadas",
                           "Configura SENTINEL_WIFI_MONITOR_IFACE para auditar el Wi-Fi."))
    else:
        filas.append(_fila(
            "PR.IR-01", _estado_por_hallazgos(acceso),
            f"{len(ctx.redes_wifi)} redes evaluadas" + ("" if acceso.empty else f", {len(acceso)} con debilidades"),
            "Usa WPA3 o WPA2-AES con PMF obligatorio y segmenta invitados/IoT.",
        ))

    # ── DETECT ───────────────────────────────────────────────────────────
    activos = [n for n, ok in ctx.sensores.items() if ok]
    total = len(ctx.sensores) or 1
    estado = CUMPLE if len(activos) >= max(2, total - 1) else PARCIAL if activos else NO_CUMPLE
    filas.append(_fila(
        "DE.CM-01", estado, f"Sensores activos: {', '.join(activos) or 'ninguno'} ({len(activos)}/{len(ctx.sensores)})",
        "Activa Suricata y Zeek además de los sniffers para cubrir firmas y metadatos.",
    ))

    filas.append(_fila(
        "DE.AE-02", CUMPLE if (ctx.analisis_ejecutado or ctx.alertas_ids) else NO_CUMPLE,
        f"{ctx.alertas_ids} alertas IDS; análisis {'ejecutado' if ctx.analisis_ejecutado else 'pendiente'}",
        "Ejecuta el análisis y revisa las alertas IDS periódicamente.",
    ))

    fuentes_datos = sum(1 for n in (ctx.flujos_tls, ctx.eventos_lan, ctx.alertas_ids) if n)
    if ctx.analisis_ejecutado and fuentes_datos >= 2:
        estado_corr = CUMPLE
    elif ctx.analisis_ejecutado:
        estado_corr = PARCIAL
    else:
        estado_corr = NO_CUMPLE
    filas.append(_fila(
        "DE.AE-03", estado_corr, f"{fuentes_datos} fuentes de datos con eventos para correlacionar",
        "Cuantas más fuentes (TLS, LAN, Suricata), más fiable es la correlación.",
    ))

    filas.append(_fila(
        "DE.AE-04", CUMPLE if ctx.analisis_ejecutado else NO_CUMPLE,
        f"{len(ctx.incidentes)} incidentes con severidad y nº de fuentes" if ctx.analisis_ejecutado
        else "Sin estimación de impacto", "Ejecuta el análisis para estimar alcance e impacto.",
    ))

    filas.append(_fila("DE.AE-06", CUMPLE, "Dashboard e informe exportable de Sentinel-X", ""))

    filas.append(_fila(
        "DE.AE-07", CUMPLE if (ctx.ti_indicadores and ctx.mitre_tecnicas) else PARCIAL if (ctx.ti_indicadores or ctx.mitre_tecnicas) else NO_CUMPLE,
        f"TI: {ctx.ti_indicadores} indicadores · MITRE: {ctx.mitre_tecnicas} técnicas",
        "Mantén TI y MITRE cargados para enriquecer las alertas.",
    ))

    if not ctx.analisis_ejecutado:
        filas.append(_fila("DE.AE-08", SIN_DATOS, "Análisis no ejecutado", "Ejecuta el análisis."))
    else:
        sin_caso = [i for i in severos if i.get("ip_principal") not in ips_con_caso]
        filas.append(_fila(
            "DE.AE-08", CUMPLE if not sin_caso else PARCIAL if len(sin_caso) < len(severos) else NO_CUMPLE,
            "Todos los incidentes altos/críticos tienen caso" if not sin_caso
            else f"{len(sin_caso)} incidente(s) alto/crítico sin caso declarado",
            "Abre un caso para cada incidente alto o crítico (pestaña Incidentes).",
        ))

    # ── RESPOND / RECOVER ────────────────────────────────────────────────
    if not ctx.casos:
        motivo = "Sin casos registrados"
        for sub in ("RS.MA-02", "RS.MA-03", "RS.AN-03", "RS.AN-06", "RS.MI-01", "RS.MI-02", "RC.RP-01"):
            filas.append(_fila(sub, SIN_DATOS, motivo, "Se evalúa en cuanto exista al menos un caso."))
    else:
        n = len(ctx.casos)
        triados = [c for c in ctx.casos if c.get("estado") != "Detectado"]
        con_notas = [c for c in ctx.casos if c.get("num_notas", 0) > 1]
        contenidos = [c for c in ctx.casos if c.get("estado") in ("Contenido", "Erradicado", "Recuperado", "Cerrado")]
        erradicados = [c for c in ctx.casos if c.get("estado") in ("Erradicado", "Recuperado", "Cerrado")]
        recuperados = [c for c in ctx.casos if c.get("estado") in ("Recuperado", "Cerrado")]

        def _prop(sub, subconjunto, texto, rec):
            k = len(subconjunto)
            estado = CUMPLE if k == n else PARCIAL if k else NO_CUMPLE
            filas.append(_fila(sub, estado, f"{k}/{n} casos {texto}", rec))

        _prop("RS.MA-02", triados, "triageados", "Pasa los casos 'Detectado' a 'En análisis' tras validarlos.")
        filas.append(_fila("RS.MA-03", CUMPLE, f"{n} casos con severidad y prioridad P1-P4", ""))
        _prop("RS.AN-03", con_notas, "con notas de análisis", "Documenta en cada caso qué ocurrió y la causa raíz.")
        filas.append(_fila("RS.AN-06", CUMPLE, "Historial de acciones con fecha y autor (solo anexar)", ""))
        _prop("RS.MI-01", contenidos, "contenidos", "Aplica las acciones de contención sugeridas en cada caso.")
        _prop("RS.MI-02", erradicados, "erradicados", "Elimina la causa raíz antes de cerrar.")
        _prop("RC.RP-01", recuperados, "recuperados", "Verifica la restauración del servicio y documenta.")

    df = pd.DataFrame(filas)
    orden = {k: i for i, k in enumerate(FUNCIONES.values())}
    df["_o"] = df["Función"].map(orden)
    return df.sort_values(["_o", "Subcategoría"]).drop(columns="_o").reset_index(drop=True)


# Niveles orientativos inspirados en los Tiers del CSF (Parcial, Informado por
# el riesgo, Repetible, Adaptativo). El CSF no define umbrales numéricos:
# esta correspondencia es una ayuda didáctica, no una calificación oficial.
def nivel_orientativo(puntuacion: float | None) -> str:
    if puntuacion is None:
        return "Sin evaluar"
    if puntuacion < 40:
        return "Nivel 1 · Parcial"
    if puntuacion < 65:
        return "Nivel 2 · Informado por el riesgo"
    if puntuacion < 85:
        return "Nivel 3 · Repetible"
    return "Nivel 4 · Adaptativo"


def puntuaciones(df_eval: pd.DataFrame) -> pd.DataFrame:
    """Puntuación 0-100 por función (las subcategorías 'Sin datos' no cuentan)."""
    filas = []
    for funcion in FUNCIONES.values():
        sub = df_eval[df_eval["Función"] == funcion] if not df_eval.empty else df_eval
        evaluadas = sub[sub["Estado"].isin(_PUNTOS.keys())] if not sub.empty else sub
        puntuacion = None
        if not evaluadas.empty:
            puntuacion = round(100 * evaluadas["Estado"].map(_PUNTOS).mean(), 1)
        filas.append({
            "Función": funcion,
            "Puntuación": puntuacion,
            "Evaluadas": len(evaluadas),
            "Total": len(sub),
            "Nivel orientativo": nivel_orientativo(puntuacion),
        })
    return pd.DataFrame(filas)


def puntuacion_global(df_puntos: pd.DataFrame) -> float | None:
    validas = df_puntos["Puntuación"].dropna()
    return round(float(validas.mean()), 1) if not validas.empty else None
