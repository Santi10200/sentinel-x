# Sentinel-X v2 — Plataforma Unificada de Seguridad de Red

Diseñado para laboratorio personal, aulas y pymes sobre **Kali Linux**. Captura,
enriquece, analiza y correlaciona eventos de red en un solo dashboard, y evalúa
la red frente a **NIST Cybersecurity Framework (CSF) 2.0** con gestión de
incidentes según **NIST SP 800-61**.

## Arquitectura (5 capas)

```
Captura          -> Scapy (TLS + LAN + Wi-Fi pasivo) · Suricata (tail -F) · Zeek (watch)
Enriquecimiento  -> JA3 completo · OUI/DNS/DHCP/Nmap · Threat Intel · MITRE ATT&CK
Análisis         -> Beaconing+DGA · Movimiento lateral · Baseline ML · Postura (exposición)
Correlación      -> Motor que une todo en incidentes con severidad combinada
Gobierno/Resp.   -> Perfil NIST CSF 2.0 · Casos SP 800-61 · Informe HTML exportable
```

## Enfoque NIST

| Función CSF 2.0 | Qué aporta Sentinel-X | Subcategorías evaluadas |
|---|---|---|
| **Gobernar (GV)** | Autoevaluación guiada (no observable en la red) | GV.OC-03, GV.PO-01, GV.RR-02 |
| **Identificar (ID)** | Inventario ARP/Nmap, mapa de flujos, servicios inseguros, CVE (NVD + CISA KEV), TI, MITRE | ID.AM-01/02/03, ID.RA-01/02/03/05 |
| **Proteger (PR)** | Protocolos en claro, Wi-Fi débil/sin PMF, configuración de servicios | PR.DS-02, PR.PS-01, PR.IR-01 (+ PR.AT-01, PR.DS-11 manuales) |
| **Detectar (DE)** | Sensores, alertas IDS, beaconing, lateral, ML, correlación | DE.CM-01, DE.AE-02/03/04/06/07/08 |
| **Responder (RS)** | Casos con prioridad P1-P4, playbook, historial solo-anexar | RS.MA-02/03, RS.AN-03/06, RS.MI-01/02 |
| **Recuperar (RC)** | Seguimiento de recuperación y cierre | RC.RP-01 (+ RC.CO-03 manual) |

Cada subcategoría muestra **estado** (Cumple / Parcial / No cumple / Sin datos),
la **evidencia** usada y una **recomendación**. La puntuación por función
promedia solo lo evaluado; los niveles 1-4 se inspiran en los Tiers del CSF,
que no definen umbrales numéricos, así que son orientativos (no es una
certificación ni una auditoría).

Los casos siguen el ciclo **Detectado → En análisis → Contenido → Erradicado →
Recuperado → Cerrado**, cada fase ligada a su subcategoría CSF. Cada cambio queda
en un historial con fecha y autor que no se edita ni se borra (RS.AN-06).

### Flujo de uso recomendado

1. **Dispositivos**: escanea la red (activa *Nmap -O -sV* para inventariar servicios) y pulsa
   *Buscar CVE en el NVD*.
2. Deja capturar tráfico unos minutos (sensores en verde en la barra lateral).
3. **Resumen**: pulsa *Ejecutar análisis completo*.
4. **NIST CSF**: revisa el perfil, completa la autoevaluación y descarga el informe.
5. **Incidentes**: declara un caso para cada incidente alto/crítico y regístralo hasta el cierre.

> Escanea únicamente redes propias o con autorización expresa por escrito.

Todo el estado entre hilos vive en `core/state.py` (nunca en
`st.session_state`) para evitar deadlocks y duplicación de hilos en cada
rerun de Streamlit. `core/orchestrator.py` garantiza arranque único.

## Instalación (Kali Linux)

```bash
# Herramientas de sistema
sudo apt update
sudo apt install -y suricata zeek nmap

# Configurar Suricata para escribir eve.json (si no está ya)
sudo suricata -c /etc/suricata/suricata.yaml -i <tu_interfaz> -D

# Configurar Zeek en modo JSON
echo 'redef LogAscii::use_json = T;' | sudo tee -a /usr/local/zeek/share/zeek/site/local.zeek
sudo zeekctl deploy

# Dependencias Python
cd sentinel_x
pip install -r requirements.txt --break-system-packages
```

## Ejecución

```bash
sudo streamlit run main.py
```

`sudo` es necesario porque ARP scan, sniffing de paquetes y `nmap -O`
requieren privilegios elevados (CAP_NET_RAW / CAP_NET_ADMIN como mínimo).

## Variables de entorno opcionales

| Variable | Default | Descripción |
|---|---|---|
| `SENTINEL_IFACE` | autodetectada | Fuerza una interfaz específica |
| `SENTINEL_SURICATA_LOG` | `/var/log/suricata/eve.json` | Ruta del log de Suricata |
| `SENTINEL_ZEEK_DIR` | `/usr/local/zeek/logs/current` | Directorio de logs Zeek |
| `SENTINEL_DB_PATH` | `data/sentinel.db` | Ruta de la base SQLite |
| `SENTINEL_LOG_PATH` | `data/sentinel_x.log` | Ruta del log de la aplicación |
| `SENTINEL_TI_ENABLED` | `true` | Activa/desactiva Threat Intelligence |
| `SENTINEL_NVD_API_KEY` | — | Clave gratuita del NVD: ~10x más consultas de CVE por minuto |
| `SENTINEL_ML_RETRAIN_MIN` | `60` | Cada cuántos minutos se reentrena el baseline ML |
| `SENTINEL_ML_MODELS_PATH` | `data/ml_modelos.joblib` | Dónde se guardan los modelos ML |
| `SENTINEL_WIFI_MONITOR_IFACE` | — | Interfaz ya en modo monitor (ej. `wlan0mon`) para auditar Wi-Fi |

## Estructura del proyecto

```
sentinel_x/
├── main.py                    # Punto de entrada Streamlit
├── core/
│   ├── config.py              # Config centralizada
│   ├── state.py               # Buffers y locks compartidos entre hilos
│   ├── database.py            # Persistencia SQLite (eventos, inventario, casos)
│   ├── network_iface.py       # Detección de interfaz
│   ├── orchestrator.py        # Arranque único de hilos de fondo
│   └── logger.py
├── modules/
│   ├── sniffer.py             # Captura Scapy (TLS + LAN + Wi-Fi)
│   ├── suricata_reader.py     # Tail en vivo de eve.json
│   ├── zeek_reader.py         # Watch de logs Zeek
│   ├── tls_analysis.py        # JA3 completo + DGA
│   ├── device_profiler.py     # ARP + OUI + DNS + DHCP + Nmap
│   ├── wifi_security.py       # Parser RSN: cifrado, AKM, PMF
│   ├── threat_intel.py        # Feodo / URLhaus / CISA KEV
│   ├── mitre_attack.py        # Mapeo a MITRE ATT&CK
│   ├── beaconing.py           # Detección C2
│   ├── lateral_movement.py    # Fan-out + puertos de riesgo
│   ├── ml_baseline.py         # IsolationForest por host, persistente y con reentreno
│   ├── correlation_engine.py  # Motor de incidentes
│   ├── postura.py             # Exposición: servicios inseguros, CVE, texto claro, Wi-Fi
│   ├── vulnerabilidades.py    # CPE de Nmap -> CVE del NVD + CISA KEV
│   ├── analisis.py            # Pipeline único (misma foto para todas las vistas)
│   ├── nist_csf.py            # Evaluación NIST CSF 2.0
│   ├── respuesta_incidentes.py# Casos y ciclo de vida SP 800-61
│   └── informe.py             # Informe HTML autocontenido
├── ui/
│   ├── helpers.py
│   ├── tab_resumen.py         # Panel general con KPIs y gráficos
│   ├── tab_nist.py            # Perfil CSF, autoevaluación, postura, informe
│   ├── tab_incidentes.py      # Incidentes correlacionados + casos
│   ├── tab_alertas.py         # Suricata + MITRE + TI
│   ├── tab_dispositivos.py    # Inventario de red
│   ├── tab_tls.py             # JA3 + beaconing
│   ├── tab_lateral.py         # Movimiento lateral + mapa de conexiones
│   ├── tab_wifi.py            # Seguridad Wi-Fi pasiva
│   └── tab_avanzado.py        # ML + Zeek + TI
└── tests/                     # pytest (sin red ni privilegios)
```

## Pruebas

```bash
cd sentinel_x
pip install pytest --break-system-packages
python3 -m pytest -q tests
```

## Notas de diseño importantes

- **Locks a nivel de módulo, nunca en `session_state`**: Streamlit
  reconstruye `session_state` de forma impredecible entre reruns; un Lock
  ahí puede quedar huérfano mientras un hilo de fondo sigue referenciando
  la instancia vieja.
- **`store=0` en todos los sniffers**: Scapy nunca acumula paquetes en RAM.
- **Buffers `deque(maxlen=N)`**: descartan automáticamente lo más viejo,
  sin crecimiento ilimitado de memoria.
- **Threat Intel nunca hace red en el camino caliente**: los feeds se
  descargan en un hilo de fondo cada hora; las consultas del sniffer son
  lookups O(1) contra sets en memoria.
- **MITRE ATT&CK con fallback offline**: si no hay red al arrancar, usa
  una tabla local de las ~20 técnicas más relevantes para NDR.
- **Beaconing sobre conexiones, no sobre paquetes**: solo los ClientHello
  (inicios de sesión TLS) cuentan para medir el intervalo de "llamada a casa".
- **Movimiento lateral sobre intentos de conexión**: el sniffer LAN marca
  SYN sin ACK (TCP) y peticiones cliente→servicio (UDP); así un gateway o un
  servidor DNS que responde a muchos clientes no parece un escáner.
- **El beacon se atribuye al host local**, que es el activo a investigar; así
  se corrobora con fan-out, ML o alertas IDS del mismo equipo.
- **Postura ≠ incidentes**: la exposición (Telnet abierto, Wi-Fi WEP) se
  muestra aparte para no inflar el número de ataques.
- **CVE bajo demanda y cacheados**: el NVD limita a 5 consultas cada 30 s sin
  clave, así que la búsqueda se lanza desde la UI (nunca en el análisis) y cada
  respuesta queda 7 días en SQLite. Un CVE presente en CISA KEV pasa a Crítico.
  La versión del banner no refleja parches retroportados por la distribución:
  los resultados son candidatos a verificar.
- **Baseline ML con memoria**: las features por minuto se guardan en SQLite y
  el modelo se reentrena solo (24 h de ventana), excluyendo los minutos que ya
  eran anómalos para que un ataque sostenido no se aprenda como normal. Una
  anomalía solo se reporta si además hay una métrica a ≥3σ de lo habitual del
  host o actividad en un horario nunca visto; así se descartan los falsos
  positivos que `contamination` introduce por diseño, y cada alerta trae su motivo.
