"""
Informe de evaluación de red en HTML autocontenido.

Pensado para entregar: un estudiante lo adjunta a su práctica, una pyme
lo comparte con dirección. No depende de CDNs ni de JavaScript; se puede
abrir sin conexión e imprimir a PDF desde el navegador.

Todo valor que proviene de la red (SSID, hostnames, firmas IDS) se escapa
con html.escape: un SSID malicioso no debe poder inyectar HTML.
"""

import datetime
import html

import pandas as pd

from modules import nist_csf

_COLOR_ESTADO = {
    nist_csf.CUMPLE: "#1a7f37", nist_csf.PARCIAL: "#b26a00",
    nist_csf.NO_CUMPLE: "#c62828", nist_csf.SIN_DATOS: "#6b7280",
}
_COLOR_SEVERIDAD = {"Crítica": "#c62828", "Alta": "#e65100", "Media": "#b26a00", "Baja": "#1565c0"}

_CSS = """
:root { color-scheme: light; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: #f6f7f9; color: #1f2328; }
main { max-width: 1100px; margin: 0 auto; padding: 32px 24px 64px; background: #fff; }
h1 { margin: 0 0 4px; font-size: 28px; }
h2 { margin-top: 40px; border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; font-size: 20px; }
.sub { color: #57606a; margin: 0 0 24px; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.kpi { border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 14px; }
.kpi b { display: block; font-size: 26px; }
.kpi span { color: #57606a; font-size: 13px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #eef0f2; vertical-align: top; }
th { background: #f6f8fa; font-weight: 600; }
.barra { display: grid; grid-template-columns: 220px 1fr 160px; gap: 12px; align-items: center; margin: 6px 0; font-size: 14px; }
.pista { background: #eef0f2; border-radius: 4px; height: 14px; overflow: hidden; }
.relleno { height: 100%; background: #2f6feb; }
.tag { display: inline-block; padding: 1px 8px; border-radius: 10px; color: #fff; font-size: 12px; white-space: nowrap; }
.nota { background: #f6f8fa; border-left: 4px solid #2f6feb; padding: 10px 14px; font-size: 13px; color: #3b434b; }
ol li { margin-bottom: 6px; }
@media print { body { background: #fff; } main { padding: 0; } h2 { page-break-after: avoid; } tr { page-break-inside: avoid; } }
"""


def _e(valor) -> str:
    if valor is None or (isinstance(valor, float) and pd.isna(valor)):
        return ""
    return html.escape(str(valor))


def _tag(texto: str, color: str) -> str:
    return f'<span class="tag" style="background:{color}">{_e(texto)}</span>'


def _tabla(df: pd.DataFrame, columnas: list[str], colorear: dict[str, dict] | None = None, max_filas: int = 200) -> str:
    if df is None or df.empty:
        return "<p class='sub'>Sin datos.</p>"
    columnas = [c for c in columnas if c in df.columns]
    colorear = colorear or {}
    cabecera = "".join(f"<th>{_e(c)}</th>" for c in columnas)
    filas = []
    for _, fila in df.head(max_filas).iterrows():
        celdas = []
        for c in columnas:
            valor = fila[c]
            if c in colorear and valor in colorear[c]:
                celdas.append(f"<td>{_tag(valor, colorear[c][valor])}</td>")
            else:
                celdas.append(f"<td>{_e(valor)}</td>")
        filas.append(f"<tr>{''.join(celdas)}</tr>")
    extra = f"<p class='sub'>Mostrando {max_filas} de {len(df)}.</p>" if len(df) > max_filas else ""
    return f"<table><thead><tr>{cabecera}</tr></thead><tbody>{''.join(filas)}</tbody></table>{extra}"


def plan_de_accion(df_nist: pd.DataFrame, df_postura: pd.DataFrame, limite: int = 12) -> list[str]:
    """Acciones priorizadas: hallazgos críticos/altos primero, luego brechas NIST."""
    acciones: list[str] = []
    if df_postura is not None and not df_postura.empty:
        graves = df_postura[df_postura["Severidad"].isin(["Crítica", "Alta"])]
        for _, h in graves.iterrows():
            texto = f"[{h['Severidad']}] {h['Activo']}: {h['Recomendación']}"
            if texto not in acciones:
                acciones.append(texto)
    if df_nist is not None and not df_nist.empty:
        for estado in (nist_csf.NO_CUMPLE, nist_csf.PARCIAL):
            for _, fila in df_nist[df_nist["Estado"] == estado].iterrows():
                if fila["Recomendación"]:
                    acciones.append(f"[{fila['Subcategoría']} · {estado}] {fila['Recomendación']}")
    return acciones[:limite]


def generar_html(resultado: dict, red: str | None = None, organizacion: str = "") -> str:
    fecha = datetime.datetime.fromtimestamp(resultado["timestamp"]).strftime("%Y-%m-%d %H:%M")
    df_nist: pd.DataFrame = resultado["df_nist"]
    df_puntos: pd.DataFrame = resultado["df_nist_puntos"]
    df_postura: pd.DataFrame = resultado["df_postura"]
    incidentes: list[dict] = resultado["incidentes"]
    casos: list[dict] = resultado.get("casos", [])
    global_ = resultado.get("nist_global")

    kpis = [
        ("Puntuación CSF", f"{global_:.0f}/100" if global_ is not None else "—"),
        ("Nivel orientativo", nist_csf.nivel_orientativo(global_).split(" · ")[0]),
        ("Dispositivos", len(resultado["inventario"])),
        ("Incidentes", len(incidentes)),
        ("Críticos / altos", sum(1 for i in incidentes if i["severidad"] in ("Crítica", "Alta"))),
        ("Hallazgos de postura", len(df_postura)),
        ("Casos abiertos", sum(1 for c in casos if c.get("estado") != "Cerrado")),
    ]
    html_kpis = "".join(f"<div class='kpi'><b>{_e(v)}</b><span>{_e(k)}</span></div>" for k, v in kpis)

    barras = []
    for _, f in df_puntos.iterrows():
        p = f["Puntuación"]
        ancho = 0 if pd.isna(p) else p
        etiqueta = "sin evaluar" if pd.isna(p) else f"{p:.0f}% · {f['Evaluadas']}/{f['Total']} evaluadas"
        barras.append(
            f"<div class='barra'><span>{_e(f['Función'])}</span>"
            f"<div class='pista'><div class='relleno' style='width:{ancho}%'></div></div>"
            f"<span>{_e(etiqueta)}</span></div>"
        )

    df_inc = pd.DataFrame([{
        "IP": i["ip_principal"], "Severidad": i["severidad"], "Fuentes": ", ".join(i["fuentes"]),
        "MITRE": ", ".join(i["mitre_tecnicas"]) or "—",
        "Resumen": " | ".join(h["descripcion"] for h in i["hallazgos"][:3]),
    } for i in incidentes])
    df_casos = pd.DataFrame([{
        "#": c["id"], "IP": c["ip"], "Estado": c["estado"], "Prioridad": c["prioridad"],
        "Severidad": c["severidad"],
        "Abierto": datetime.datetime.fromtimestamp(c["creado"]).strftime("%Y-%m-%d %H:%M"),
    } for c in casos])

    acciones = plan_de_accion(df_nist, df_postura)
    html_acciones = "".join(f"<li>{_e(a)}</li>" for a in acciones) or "<li>Sin acciones pendientes.</li>"

    titulo = "Informe de seguridad de red" + (f" · {organizacion}" if organizacion else "")
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(titulo)}</title><style>{_CSS}</style></head>
<body><main>
<h1>{_e(titulo)}</h1>
<p class="sub">Generado por Sentinel-X el {_e(fecha)}{' · red ' + _e(red) if red else ''} · Referencia: NIST CSF 2.0 y NIST SP 800-61</p>

<h2>1. Resumen ejecutivo</h2>
<div class="kpis">{html_kpis}</div>

<h2>2. Perfil actual NIST CSF 2.0</h2>
{''.join(barras)}
<p class="nota">La puntuación promedia las subcategorías evaluadas (Cumple = 1, Parcial = 0,5, No cumple = 0).
Las marcadas «Sin datos» no cuentan. Los niveles 1-4 se inspiran en los Tiers del CSF, que no definen
umbrales numéricos: úsalos como orientación para priorizar, no como certificación.</p>
{_tabla(df_nist, ["Subcategoría", "Resultado esperado", "Estado", "Evidencia", "Recomendación", "Tipo"],
        {"Estado": _COLOR_ESTADO})}

<h2>3. Plan de acción priorizado</h2>
<ol>{html_acciones}</ol>

<h2>4. Incidentes correlacionados (DETECT)</h2>
{_tabla(df_inc, ["IP", "Severidad", "Fuentes", "MITRE", "Resumen"], {"Severidad": _COLOR_SEVERIDAD}, 50)}

<h2>5. Casos de respuesta (RESPOND · SP 800-61)</h2>
{_tabla(df_casos, ["#", "IP", "Estado", "Prioridad", "Severidad", "Abierto"], {"Severidad": _COLOR_SEVERIDAD})}

<h2>6. Hallazgos de postura (IDENTIFY · PROTECT)</h2>
{_tabla(df_postura, ["Severidad", "Categoría", "Activo", "Detalle", "NIST CSF", "MITRE", "Recomendación"],
        {"Severidad": _COLOR_SEVERIDAD})}

<h2>7. Metodología y limitaciones</h2>
<p class="nota">Sentinel-X observa la red de forma pasiva (Scapy, Suricata, Zeek, captura Wi-Fi) y de forma activa
solo cuando el usuario lanza un escaneo ARP/Nmap. Los resultados reflejan lo observado durante la ventana de
captura: un host apagado o un tráfico no generado no aparece. Las subcategorías de gobierno, formación y copias
de seguridad se basan en la autoevaluación del responsable. Realiza escaneos únicamente en redes propias o con
autorización expresa.</p>
</main></body></html>"""
