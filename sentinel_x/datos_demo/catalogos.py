"""
Catálogos usados para generar personas FICTICIAS de Latinoamérica.

Los nombres y apellidos son de uso común en cada país y se combinan al azar,
por lo que cualquier coincidencia con una persona real es casual. Los
documentos de identidad NO siguen el formato oficial (llevan el prefijo
"DEMO-" y no tienen dígito verificador válido), así nunca pueden confundirse
con un documento real.
"""

# Cada país define: nombres, apellidos, tipo de documento, prefijo telefónico,
# ciudades y la norma de protección de datos personales aplicable.
PAISES = {
    "MX": {
        "pais": "México",
        "nombres_f": ["María", "Guadalupe", "Fernanda", "Ximena", "Daniela", "Sofía", "Valeria", "Regina"],
        "nombres_m": ["José", "Juan", "Luis", "Carlos", "Miguel", "Diego", "Santiago", "Emiliano"],
        "apellidos": ["Hernández", "García", "Martínez", "López", "González", "Pérez", "Rodríguez", "Sánchez", "Ramírez", "Cruz"],
        "tipo_documento": "CURP",
        "prefijo_tel": "+52",
        "ciudades": ["Ciudad de México", "Guadalajara", "Monterrey", "Puebla", "Mérida"],
        "norma": "LFPDPPP (Ley Federal de Protección de Datos Personales en Posesión de los Particulares)",
    },
    "CO": {
        "pais": "Colombia",
        "nombres_f": ["Valentina", "Isabella", "Mariana", "Laura", "Camila", "Paula", "Natalia", "Juliana"],
        "nombres_m": ["Santiago", "Sebastián", "Andrés", "Juan Pablo", "Camilo", "Felipe", "Mateo", "Julián"],
        "apellidos": ["Rodríguez", "Gómez", "Martínez", "Restrepo", "Díaz", "Vargas", "Moreno", "Castro", "Ospina", "Rojas"],
        "tipo_documento": "CC",
        "prefijo_tel": "+57",
        "ciudades": ["Bogotá", "Medellín", "Cali", "Barranquilla", "Bucaramanga"],
        "norma": "Ley 1581 de 2012 y Decreto 1377 de 2013 (Habeas Data)",
    },
    "AR": {
        "pais": "Argentina",
        "nombres_f": ["Martina", "Lucía", "Agustina", "Florencia", "Micaela", "Julieta", "Abril", "Catalina"],
        "nombres_m": ["Matías", "Nicolás", "Facundo", "Tomás", "Joaquín", "Lautaro", "Franco", "Agustín"],
        "apellidos": ["González", "Rodríguez", "Fernández", "López", "Gómez", "Díaz", "Romero", "Sosa", "Álvarez", "Benítez"],
        "tipo_documento": "DNI",
        "prefijo_tel": "+54",
        "ciudades": ["Buenos Aires", "Córdoba", "Rosario", "Mendoza", "La Plata"],
        "norma": "Ley 25.326 de Protección de los Datos Personales",
    },
    "CL": {
        "pais": "Chile",
        "nombres_f": ["Antonella", "Josefa", "Constanza", "Javiera", "Fernanda", "Trinidad", "Catalina", "Isidora"],
        "nombres_m": ["Benjamín", "Vicente", "Cristóbal", "Maximiliano", "Ignacio", "Gaspar", "Agustín", "Tomás"],
        "apellidos": ["González", "Muñoz", "Rojas", "Díaz", "Pérez", "Soto", "Contreras", "Silva", "Morales", "Fuentes"],
        "tipo_documento": "RUN",
        "prefijo_tel": "+56",
        "ciudades": ["Santiago", "Valparaíso", "Concepción", "Antofagasta", "Temuco"],
        "norma": "Ley 19.628 y Ley 21.719 de Protección de Datos Personales",
    },
    "PE": {
        "pais": "Perú",
        "nombres_f": ["Ana Lucía", "Milagros", "Rosa", "Kiara", "Alessandra", "Andrea", "Fiorella", "Luciana"],
        "nombres_m": ["Jorge", "Renzo", "Diego", "Álvaro", "Piero", "Rodrigo", "Gonzalo", "César"],
        "apellidos": ["Quispe", "Flores", "Sánchez", "Rodríguez", "García", "Mamani", "Huamán", "Chávez", "Ramos", "Torres"],
        "tipo_documento": "DNI",
        "prefijo_tel": "+51",
        "ciudades": ["Lima", "Arequipa", "Trujillo", "Cusco", "Piura"],
        "norma": "Ley 29733 de Protección de Datos Personales",
    },
    "BR": {
        "pais": "Brasil",
        "nombres_f": ["Ana", "Beatriz", "Juliana", "Larissa", "Gabriela", "Fernanda", "Letícia", "Mariana"],
        "nombres_m": ["João", "Pedro", "Lucas", "Gabriel", "Rafael", "Gustavo", "Thiago", "Felipe"],
        "apellidos": ["Silva", "Santos", "Oliveira", "Souza", "Pereira", "Costa", "Rodrigues", "Almeida", "Nascimento", "Lima"],
        "tipo_documento": "CPF",
        "prefijo_tel": "+55",
        "ciudades": ["São Paulo", "Rio de Janeiro", "Belo Horizonte", "Curitiba", "Recife"],
        "norma": "Lei 13.709/2018 (LGPD)",
    },
    "EC": {
        "pais": "Ecuador",
        "nombres_f": ["Doménica", "Emilia", "Paula", "Nicole", "Karla", "Gabriela", "Mishel", "Ariana"],
        "nombres_m": ["Byron", "Alexis", "Jhon", "Kevin", "Wilson", "Esteban", "Danilo", "Fabricio"],
        "apellidos": ["Zambrano", "Mendoza", "Vera", "Cedeño", "Andrade", "Guerrero", "Castillo", "Paredes", "Salazar", "Villacís"],
        "tipo_documento": "CI",
        "prefijo_tel": "+593",
        "ciudades": ["Quito", "Guayaquil", "Cuenca", "Manta", "Loja"],
        "norma": "Ley Orgánica de Protección de Datos Personales (2021)",
    },
    "UY": {
        "pais": "Uruguay",
        "nombres_f": ["Valentina", "Sofía", "Lucía", "Victoria", "Florencia", "Romina", "Paula", "Agustina"],
        "nombres_m": ["Federico", "Gonzalo", "Martín", "Rodrigo", "Diego", "Bruno", "Santiago", "Emiliano"],
        "apellidos": ["Rodríguez", "Pereira", "Fernández", "Silva", "Martínez", "Sosa", "Núñez", "Acosta", "Cabrera", "Olivera"],
        "tipo_documento": "CI",
        "prefijo_tel": "+598",
        "ciudades": ["Montevideo", "Salto", "Paysandú", "Maldonado", "Rivera"],
        "norma": "Ley 18.331 de Protección de Datos Personales",
    },
}

# Roles típicos en el control de acceso de un lugar privado.
ROLES = {
    "empleado":    {"peso": 45, "nivel_acceso": (2, 4), "vigencia_dias": 365},
    "contratista": {"peso": 15, "nivel_acceso": (1, 3), "vigencia_dias": 90},
    "visitante":   {"peso": 25, "nivel_acceso": (1, 1), "vigencia_dias": 1},
    "residente":   {"peso": 10, "nivel_acceso": (2, 3), "vigencia_dias": 365},
    "seguridad":   {"peso": 5,  "nivel_acceso": (4, 5), "vigencia_dias": 365},
}

# Zonas del lugar privado con el nivel mínimo de acceso que exigen.
ZONAS = {
    "Recepción": 1,
    "Parqueadero": 1,
    "Oficinas": 2,
    "Áreas comunes": 2,
    "Bodega": 3,
    "Sala de servidores": 4,
    "Centro de monitoreo": 5,
}

FINALIDAD_TRATAMIENTO = (
    "Control de acceso y seguridad física de las instalaciones. "
    "Datos sintéticos generados con fines educativos."
)
