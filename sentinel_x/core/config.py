"""
Configuración centralizada de Sentinel-X.
Todo valor ajustable vive aquí o en variables de entorno SENTINEL_*.
"""

import os


def _bool_env(nombre: str, default: bool) -> bool:
    val = os.getenv(nombre)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


CONFIG = {
    # ── Red ──────────────────────────────────────────────────────────────
    "interfaz_red": os.getenv("SENTINEL_IFACE"),  # None => autodetección
    "interfaces_excluidas": ["lo", "docker0", "virbr0", "br-"],

    # ── Fuentes de eventos ───────────────────────────────────────────────
    "archivo_suricata": os.getenv("SENTINEL_SURICATA_LOG", "/var/log/suricata/eve.json"),
    "dir_zeek_logs": os.getenv("SENTINEL_ZEEK_DIR", "/usr/local/zeek/logs/current"),
    "rutas_dhcp_leases": [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dhcp/dhcpd.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
        "/tmp/dhcp.leases",
    ],

    # ── Buffers en memoria ───────────────────────────────────────────────
    "buffer_max_flujos_tls": int(os.getenv("SENTINEL_MAX_FLOWS", "10000")),
    "buffer_max_eventos_lan": int(os.getenv("SENTINEL_MAX_LAN_EVENTS", "20000")),
    "buffer_max_alertas": int(os.getenv("SENTINEL_MAX_ALERTS", "5000")),
    "buffer_max_zeek": int(os.getenv("SENTINEL_MAX_ZEEK", "20000")),
    "buffer_max_incidentes": int(os.getenv("SENTINEL_MAX_INCIDENTS", "2000")),

    # ── Beaconing / C2 ───────────────────────────────────────────────────
    "beacon_min_paquetes": 5,
    "beacon_umbral_cv": 0.10,
    "dga_umbral_entropia": 3.5,
    "dga_tlds_sospechosos": {"tk", "ml", "cf", "ga", "gq", "xyz", "top", "club"},

    # ── Movimiento lateral ───────────────────────────────────────────────
    "lateral_puertos_riesgo": {
        22: "SSH", 23: "Telnet", 135: "RPC", 139: "NetBIOS",
        445: "SMB", 3389: "RDP", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS",
        1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
    },
    "lateral_umbral_fanout": 8,       # hosts distintos contactados / ventana
    "lateral_ventana_seg": 120,       # ventana deslizante para fan-out

    # ── Baseline ML ──────────────────────────────────────────────────────
    "ml_ventana_entrenamiento_horas": 24,
    "ml_min_muestras_entrenamiento": 30,
    "ml_contaminacion": 0.05,          # proporción esperada de anomalías
    "ml_reentreno_min": int(os.getenv("SENTINEL_ML_RETRAIN_MIN", "60")),
    "ml_ventana_deteccion_min": 60,     # minutos recientes que puntúa el análisis
    "ml_umbral_sigma": 3.0,             # desviación mínima para reportar una anomalía
    "ml_modelos_path": os.getenv("SENTINEL_ML_MODELS_PATH", "data/ml_modelos.joblib"),

    # ── Threat Intelligence ─────────────────────────────────────────────
    "ti_habilitado": _bool_env("SENTINEL_TI_ENABLED", True),
    "ti_ttl_cache_horas": 24,
    "ti_timeout_seg": 3,
    "ti_feodo_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "ti_urlhaus_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "ti_kev_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "ti_actualizacion_seg": 3600,

    # ── NVD (CVE) ────────────────────────────────────────────────────────
    "nvd_api_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "nvd_api_key": os.getenv("SENTINEL_NVD_API_KEY"),  # opcional: 10x más peticiones
    "nvd_timeout_seg": 20,
    "nvd_cache_dias": 7,

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────
    "mitre_stix_url": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    ),

    # Bases de prefijos MAC que ya trae Kali (nmap y Wireshark): sin consultas externas.
    "rutas_oui_sistema": [
        "/usr/share/wireshark/manuf",
        "/usr/share/nmap/nmap-mac-prefixes",
    ],

    # ── Nmap ─────────────────────────────────────────────────────────────
    "nmap_timeout_seg": 25,
    "nmap_version_intensity": 3,

    # ── Persistencia ─────────────────────────────────────────────────────
    # Ruta relativa al directorio de ejecución, portable entre instalaciones Kali.
    "db_path": os.getenv("SENTINEL_DB_PATH", "data/sentinel.db"),
    "db_retencion_dias": 7,
    "db_max_tamano_mb": 500,

    # ── UI ───────────────────────────────────────────────────────────────
    "auto_refresh_seg_default": 5,

    # Wi-Fi (solo captura pasiva con una interfaz ya puesta en modo monitor).
    # Si queda en None, Sentinel-X no inicia ningún sniffer 802.11.
    "wifi_monitor_iface": os.getenv("SENTINEL_WIFI_MONITOR_IFACE"),
}
