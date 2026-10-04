# Sentinel-X v2 — Plataforma Unificada de Seguridad de Red

Diseñado para laboratorio personal sobre **Kali Linux**. Captura, enriquece,
analiza y correlaciona eventos de red en un solo dashboard.

## Arquitectura (4 capas)

```
Captura          -> Scapy (TLS + LAN) · Suricata (tail -F) · Zeek (watch)
Enriquecimiento  -> JA3 completo · OUI/DNS/DHCP/Nmap · Threat Intel · MITRE ATT&CK
Análisis         -> Beaconing+DGA · Movimiento lateral · Baseline ML (IsolationForest)
Correlación      -> Motor que une todo en incidentes con severidad combinada
```

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
| `SENTINEL_TI_ENABLED` | `true` | Activa/desactiva Threat Intelligence |

## Estructura del proyecto

```
sentinel_x/
├── main.py                    # Punto de entrada Streamlit
├── core/
│   ├── config.py              # Config centralizada
│   ├── state.py                # Buffers y locks compartidos entre hilos
│   ├── database.py             # Persistencia SQLite
│   ├── network_iface.py        # Detección de interfaz
│   ├── orchestrator.py         # Arranque único de hilos de fondo
│   └── logger.py
├── modules/
│   ├── sniffer.py               # Captura Scapy (TLS + LAN)
│   ├── suricata_reader.py       # Tail en vivo de eve.json
│   ├── zeek_reader.py            # Watch de logs Zeek
│   ├── tls_analysis.py           # JA3 completo + DGA
│   ├── device_profiler.py        # ARP + OUI + DNS + DHCP + Nmap
│   ├── threat_intel.py            # Feodo / URLhaus / CISA KEV
│   ├── mitre_attack.py             # Mapeo a MITRE ATT&CK
│   ├── beaconing.py                 # Detección C2
│   ├── lateral_movement.py           # Fan-out + puertos de riesgo
│   ├── ml_baseline.py                 # IsolationForest por host
│   └── correlation_engine.py           # Motor de incidentes
└── ui/
    ├── helpers.py
    ├── tab_incidentes.py        # Pestaña 1: vista correlacionada
    ├── tab_alertas.py            # Pestaña 2: Suricata + MITRE + TI
    ├── tab_dispositivos.py        # Pestaña 3: inventario de red
    ├── tab_tls.py                  # Pestaña 4: JA3 + beaconing
    ├── tab_lateral.py                # Pestaña 5: movimiento lateral
    └── tab_avanzado.py                # Pestaña 6: ML + Zeek + TI
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

## Datos de demostración: personas ficticias (control de acceso)

Para fines educativos y de prueba, `datos_demo/` genera una base SQLite
separada (`data/personas_demo.db`) con personas **ficticias** de
Latinoamérica (MX, CO, AR, CL, PE, BR, EC, UY) y su historial de accesos a
zonas de un lugar privado.

```bash
cd sentinel_x
python -m datos_demo.generar_personas --cantidad 200 --semilla 42
python -m datos_demo.generar_personas --csv data/personas_demo.csv   # exporta también a CSV
```

Tablas: `personas`, `zonas` (con nivel mínimo requerido) y
`registros_acceso` (entradas/salidas permitidas o denegadas según nivel y
estado de la persona).

Criterios de protección de datos aplicados (Ley 1581/2012 CO, LGPD BR,
LFPDPPP MX, Ley 25.326 AR, Ley 19.628/21.719 CL, Ley 29733 PE, LOPDP EC,
Ley 18.331 UY):

- **Datos sintéticos**: nombres combinados al azar; cada fila tiene
  `es_sintetico = 1`. No usar este generador para cargar datos reales.
- **Identificadores no reales**: documentos con prefijo `DEMO-`, correos en
  `example.com` (dominio reservado, RFC 2606) y teléfonos no asignables.
- **Minimización**: sin biometría, domicilio ni datos sensibles; solo año de
  nacimiento.
- **Finalidad, consentimiento y retención** explícitos por registro
  (`finalidad`, `consentimiento`, `fecha_expiracion`, `norma_aplicable`).

Si el sistema se usa con personas reales, se necesita además: aviso de
privacidad, autorización previa del titular, procedimiento para ejercer
derechos (acceso, rectificación, supresión), y registro de la base ante la
autoridad cuando la ley lo exija (p. ej. RNBD de la SIC en Colombia).
