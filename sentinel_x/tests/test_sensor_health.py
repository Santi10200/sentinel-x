from modules import sensor_health


def test_resumen_expone_fuentes_y_capacidad():
    datos = sensor_health.resumen()
    assert datos["estado_global"] in {"Operativo", "Atención", "Crítico"}
    assert {fila["Fuente"] for fila in datos["fuentes"]} >= {"Captura TLS", "Suricata", "Zeek"}
    assert all("Uso (%)" in fila for fila in datos["capacidad"])
