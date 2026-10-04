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
│   ├── correlation_engine.py           # Motor de incidentes
│   └── face_verify.py                  # Verificación facial 1:1 (opcional)
├── tests/
│   └── test_face_verify.py
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

## Módulo opcional: verificación facial 1:1

Laboratorio para estudiar cómo funciona (y cómo falla) la biometría facial.
Compara **dos imágenes locales** y responde si son de la misma persona; no
busca ni identifica a nadie contra fuentes externas. Usa solo fotos propias,
de personas que han dado su consentimiento o datasets académicos con licencia
(p. ej. LFW).

```bash
pip install deepface tf-keras --break-system-packages

# ¿Son la misma persona?
python -m modules.face_verify verificar foto_a.jpg foto_b.jpg

# Evaluar el sistema: FAR / FRR por umbral y EER
#   pares.csv -> img1,img2,misma_persona (1/0)
python -m modules.face_verify evaluar pares.csv --salida far_frr.csv

# Otro modelo
python -m modules.face_verify --modelo Facenet512 verificar a.jpg b.jpg
```

- **FAR** (False Accept Rate): impostores aceptados como genuinos.
- **FRR** (False Reject Rate): genuinos rechazados.
- **EER**: punto donde FAR = FRR; cuanto menor, mejor discrimina el modelo.

Una imagen con cero o varios rostros se rechaza: en verificación 1:1 eso es
ambiguo. Un resultado positivo es una probabilidad con error, nunca una prueba
de identidad.

Tests (no necesitan DeepFace): `python -m pytest tests -q`

