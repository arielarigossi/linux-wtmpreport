import struct
import os
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from collections import Counter
import gzip
import glob
import re
import sqlite3
from weasyprint import HTML
import sys
import logging

# ================================
# Configuración de Logging
# ================================
logging.basicConfig(
    filename='analisis_logs.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s:%(message)s'
)

# ================================
# Funciones Utilitarias
# ================================

def solicitar_directorio_logs():
    """
    Solicita al usuario el directorio que contiene los archivos de logs.
    Por defecto utiliza '/var/log/' si no se proporciona entrada.
    """
    ruta = input(
        "Ingresa la ruta al directorio que contiene los archivos de logs (predeterminado: /var/log/): "
    )
    if not ruta:
        ruta = "/var/log/"
    if not os.path.exists(ruta):
        logging.error("Directorio no encontrado: %s", ruta)
        print("Directorio no encontrado. Por favor, verifica la ruta e intenta nuevamente.")
        sys.exit(1)
    logging.info("Directorio de logs establecido en: %s", ruta)
    return ruta

def determinar_rango_tiempo_wtmp(ruta):
    """
    Determina el rango de tiempo analizando los archivos 'wtmp'.
    Retorna una tupla de (fecha_más_antigua, fecha_más_reciente).
    """
    archivos_wtmp = glob.glob(os.path.join(ruta, "wtmp*"))
    if not archivos_wtmp:
        logging.error("No se encontraron archivos wtmp en el directorio: %s", ruta)
        print("No se encontraron archivos wtmp en el directorio especificado.")
        return None, None

    mas_antigua = None
    mas_reciente = None

    for archivo in archivos_wtmp:
        logging.info("Procesando archivo wtmp: %s", archivo)
        try:
            for entrada in abrir_wtmp(archivo):
                if entrada['tipo'] == 'PROCESO_USUARIO' and entrada['timestamp']:
                    timestamp = entrada['timestamp']
                    if not mas_antigua or timestamp < mas_antigua:
                        mas_antigua = timestamp
                    if not mas_reciente or timestamp > mas_reciente:
                        mas_reciente = timestamp
        except Exception as e:
            logging.error("Error al procesar el archivo wtmp %s: %s", archivo, e)
            continue

    if not mas_antigua or not mas_reciente:
        logging.warning("No se pudo determinar el rango de tiempo a partir de los archivos wtmp.")
        print("No se pudo determinar el rango de tiempo a partir de los archivos wtmp.")
        return None, None

    logging.info("Rango de tiempo determinado a partir de wtmp: %s a %s", mas_antigua, mas_reciente)
    return mas_antigua, mas_reciente

def solicitar_rango_tiempo(antigua, reciente):
    """
    Solicita al usuario confirmar el rango de tiempo inferido o ingresar un rango personalizado.
    Retorna una tupla de (fecha_inicio, fecha_fin).
    """
    print(f"\nRango de Tiempo Inferido a partir de archivos wtmp:")
    print(f"Desde: {antigua.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Hasta: {reciente.strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info("Rango de tiempo inferido: %s a %s", antigua, reciente)

    while True:
        eleccion = input("\n¿Es correcto este rango de tiempo? (S/N): ").strip().lower()
        if eleccion == 's':
            logging.info("Usuario confirmó el rango de tiempo inferido.")
            return antigua, reciente
        elif eleccion == 'n':
            print("\nPor favor, ingresa un rango de tiempo personalizado.")
            return solicitar_rango_tiempo_personalizado()
        else:
            print("Entrada inválida. Por favor, ingresa 'S' o 'N'.")

def solicitar_rango_tiempo_personalizado():
    """
    Solicita al usuario ingresar un rango de tiempo personalizado.
    Retorna una tupla de (fecha_inicio, fecha_fin).
    """
    while True:
        try:
            desde_str = input("Ingresa la fecha de inicio (Desde) [AAAA-MM-DD]: ")
            hasta_str = input("Ingresa la fecha de fin (Hasta) [AAAA-MM-DD]: ")
            desde = datetime.strptime(desde_str, "%Y-%m-%d")
            hasta = datetime.strptime(hasta_str, "%Y-%m-%d")
            if desde > hasta:
                print("La fecha de inicio debe ser anterior a la fecha de fin. Intenta nuevamente.")
                continue
            # Ajustar para incluir todo el día de fin
            hasta = hasta + timedelta(days=1) - timedelta(seconds=1)
            logging.info("Usuario ingresó rango de tiempo personalizado: %s a %s", desde, hasta)
            print(f"Rango de tiempo personalizado establecido desde {desde} hasta {hasta}.")
            return desde, hasta
        except ValueError:
            print("Formato de fecha inválido. Por favor, usa AAAA-MM-DD.")

def abrir_wtmp(ruta_archivo):
    """
    Generador para leer y parsear archivos 'wtmp'.
    Genera diccionarios representando cada entrada.
    Nota: El formato de struct puede necesitar ajustes según el sistema.
    """
    # Formato común de estructura utmp para muchos sistemas Linux (ajustar si es necesario)
    # Ejemplo de formato para sistemas Linux de 64 bits
    UTMP_STRUCT_FORMAT = "hi32s4s32s256shhiII4I20s"
    UTMP_STRUCT_SIZE = struct.calcsize(UTMP_STRUCT_FORMAT)

    # Abrir el archivo (soporta gzip si es necesario)
    abrir_func = gzip.open if ruta_archivo.endswith(".gz") else open
    modo = "rb"

    with abrir_func(ruta_archivo, modo) as f:
        while True:
            datos = f.read(UTMP_STRUCT_SIZE)
            if not datos or len(datos) != UTMP_STRUCT_SIZE:
                break
            try:
                desempaquetado = struct.unpack(UTMP_STRUCT_FORMAT, datos)
                ut_type = desempaquetado[0]
                # Solo interesado en entradas PROCESO_USUARIO (tipo 7)
                if ut_type == 7:
                    ut_tv_sec = desempaquetado[9]
                    try:
                        timestamp = datetime.fromtimestamp(ut_tv_sec)
                    except (OSError, OverflowError, ValueError):
                        timestamp = None
                    usuario = desempaquetado[4].decode("utf-8", "ignore").strip("\x00")
                    terminal = desempaquetado[2].decode("utf-8", "ignore").strip("\x00")
                    host = desempaquetado[5].decode("utf-8", "ignore").strip("\x00")
                    yield {
                        'tipo': 'PROCESO_USUARIO',
                        'usuario': usuario,
                        'terminal': terminal,
                        'host': host,
                        'timestamp': timestamp
                    }
                else:
                    yield {
                        'tipo': 'OTRO',
                        'timestamp': None
                    }
            except struct.error as e:
                logging.error("Error al desempaquetar estructura en %s: %s", ruta_archivo, e)
                yield {
                    'tipo': 'OTRO',
                    'timestamp': None
                }

def crear_carpeta_salida():
    """
    Crea un directorio de salida con una marca de tiempo y PID para almacenar reportes y gráficos.
    """
    marca_tiempo = datetime.now().strftime("%Y%m%d-%H%M%S")
    pid = os.getpid()
    nombre_carpeta = f"informe_logs-{marca_tiempo}_PID{pid}"
    os.makedirs(nombre_carpeta, exist_ok=True)
    logging.info("Carpeta de salida creada: %s", nombre_carpeta)
    print(f"\nCarpeta de salida creada: {nombre_carpeta}")
    return nombre_carpeta

def inicializar_base_datos(carpeta_salida):
    """
    Inicializa la base de datos SQLite con las tablas necesarias y configuraciones optimizadas.
    """
    ruta_db = os.path.join(carpeta_salida, "analisis_logs.db")
    conn = sqlite3.connect(ruta_db)
    cursor = conn.cursor()

    # Optimización de SQLite para inserciones más rápidas
    cursor.execute("PRAGMA synchronous = OFF;")
    cursor.execute("PRAGMA journal_mode = MEMORY;")
    cursor.execute("PRAGMA temp_store = MEMORY;")
    cursor.execute("PRAGMA cache_size = 1000000;")  # Ajustar según la memoria disponible

    # Crear tablas
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT,
            hora TEXT,
            terminal TEXT,
            host TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS intentos_autenticacion (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT,
            hora TEXT,
            servicio TEXT,
            ip TEXT,
            resultado TEXT,
            mensaje TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comandos_sudo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT,
            hora TEXT,
            tty TEXT,
            pwd TEXT,
            usuario_destino TEXT,
            comando TEXT,
            mensaje TEXT,
            timestamp TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS errores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            archivo TEXT,
            numero_linea INTEGER,
            contenido_linea TEXT,
            tiempo_inferido TEXT
        )
    """)

    # Crear índices para optimizar consultas
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logins_timestamp ON logins (timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_intentos_autenticacion_timestamp ON intentos_autenticacion (timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_comandos_sudo_timestamp ON comandos_sudo (timestamp)")

    conn.commit()
    logging.info("Base de datos SQLite inicializada en %s", ruta_db)
    print("Base de datos inicializada correctamente.")
    logging.info("Base de datos inicializada correctamente.")
    return conn

def mapear_archivos_secure(ruta, desde, hasta):
    """
    Asocia los archivos 'secure' con el rango de tiempo determinado basado en el nombre del archivo o la fecha de modificación.
    Retorna una lista de tuplas (ruta_archivo, año_inferido, mes_inferido).
    """
    archivos_secure = glob.glob(os.path.join(ruta, "secure*"))
    if not archivos_secure:
        logging.warning("No se encontraron archivos secure en el directorio: %s", ruta)
        print("No se encontraron archivos secure en el directorio especificado.")
        return []

    archivos_mapeados = []

    for archivo in archivos_secure:
        nombre_archivo = os.path.basename(archivo)
        logging.info("Mapeando archivo secure: %s", archivo)
        # Patrones para coincidir:
        # secure, secure.log, secure-AAAA-MM-DD.log, secure.log.1, secure.log.gz, etc.
        match = re.match(r"secure(?:-(\d{4})(\d{2})(\d{2}))?(?:\.log(?:\.\d+)?(?:\.gz)?)?$", nombre_archivo)
        if match:
            año, mes, dia = match.groups()
            if año and mes and dia:
                try:
                    fecha_inferida = datetime(int(año), int(mes), int(dia))
                except ValueError:
                    fecha_inferida = None
            else:
                # Inferir a partir de la fecha de modificación
                try:
                    mtime = os.path.getmtime(archivo)
                    fecha_inferida = datetime.fromtimestamp(mtime)
                except Exception as e:
                    logging.error("Error al inferir fecha para %s: %s", archivo, e)
                    fecha_inferida = None

            if fecha_inferida:
                if desde <= fecha_inferida <= hasta:
                    archivos_mapeados.append((archivo, fecha_inferida.year, fecha_inferida.month))
                    logging.info("Archivo secure %s mapeado a fecha: %s", archivo, fecha_inferida)
                else:
                    logging.info("Archivo secure %s está fuera del rango de tiempo. Saltando.", archivo)
            else:
                logging.warning("No se pudo inferir la fecha para el archivo secure: %s. Saltando.", archivo)
        else:
            logging.warning("Archivo secure %s no coincide con los patrones esperados. Saltando.", archivo)

    return archivos_mapeados

def parsear_unico_secure(ruta_archivo, conn, año, mes, desde, hasta, tamaño_lote=5000):
    """
    Parsea un único archivo 'secure' y almacena las entradas relevantes dentro del rango de tiempo en la base de datos.
    Las entradas fuera del rango se registran en la tabla 'errores'.
    Retorna el número de líneas procesadas.
    """
    cursor = conn.cursor()
    lote_auth = []
    lote_sudo = []
    numero_linea = 0
    lineas_procesadas = 0

    try:
        abrir_func = gzip.open if ruta_archivo.endswith(".gz") else open
        modo = "rt"
        with abrir_func(ruta_archivo, modo, encoding="utf-8", errors="ignore") as f_in:
            for linea in f_in:
                numero_linea += 1
                # Expresión regular para parsear líneas de secure
                regex = r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)(?:\[\d+\])?:\s+(.*)$"
                match = re.match(regex, linea)
                if match:
                    hora_str, hostname, servicio, mensaje = match.groups()
                    # Parsear la hora
                    try:
                        hora = datetime.strptime(hora_str, "%b %d %H:%M:%S")
                        hora = hora.replace(year=año, month=mes)
                        # Manejar rollover de año
                        if hora > hasta:
                            hora = hora - timedelta(days=365)
                    except ValueError as ve:
                        logging.error("Error al parsear hora en %s línea %d: %s", ruta_archivo, numero_linea, ve)
                        cursor.execute(
                            """
                            INSERT INTO errores (archivo, numero_linea, contenido_linea, tiempo_inferido)
                            VALUES (?, ?, ?, ?)
                            """,
                            (ruta_archivo, numero_linea, f"Error al parsear hora: {ve}", "N/A"),
                        )
                        continue

                    # Verificar si está dentro del rango de tiempo
                    if not (desde <= hora <= hasta):
                        logging.info("Entrada fuera del rango de tiempo en %s línea %d: %s", ruta_archivo, numero_linea, hora)
                        cursor.execute(
                            """
                            INSERT INTO errores (archivo, numero_linea, contenido_linea, tiempo_inferido)
                            VALUES (?, ?, ?, ?)
                            """,
                            (ruta_archivo, numero_linea, f"Entrada fuera del rango de tiempo: {hora}", hora.strftime("%Y-%m-%d %H:%M:%S")),
                        )
                        continue

                    # Determinar si es un intento de autenticación
                    if any(palabra in mensaje for palabra in ["Failed password for", "Accepted password for", "authentication failure", "Invalid user"]):
                        usuario_match = re.search(r"for (\S+)", mensaje)
                        ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", mensaje)
                        resultado = "Fallido" if "Failed" in mensaje or "authentication failure" in mensaje or "Invalid user" in mensaje else "Aceptado"
                        usuario = usuario_match.group(1) if usuario_match else "Desconocido"
                        ip = ip_match.group(1) if ip_match else "Desconocido"
                        hora_str_completa = hora.strftime("%Y-%m-%d %H:%M:%S")
                        lote_auth.append((
                            usuario,
                            hora_str_completa,
                            servicio,
                            ip,
                            resultado,
                            mensaje,
                            hora_str_completa
                        ))

                        if len(lote_auth) >= tamaño_lote:
                            cursor.executemany(
                                """
                                INSERT INTO intentos_autenticacion (usuario, hora, servicio, ip, resultado, mensaje, timestamp)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                """,
                                lote_auth
                            )
                            conn.commit()
                            logging.info("Insertados %d intentos de autenticación desde %s", len(lote_auth), ruta_archivo)
                            print(f"Insertados {len(lote_auth)} intentos de autenticación desde {ruta_archivo}")
                            lineas_procesadas += len(lote_auth)
                            lote_auth = []

                    # Determinar si es un comando sudo
                    elif servicio.startswith("sudo"):
                        mensaje = mensaje.strip()
                        # Expresión regular para comandos sudo
                        sudo_regex = r"^(\S+)\s*:\s+TTY=(\S+)\s+;\s+PWD=(\S+)\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)$"
                        sudo_match = re.match(sudo_regex, mensaje)
                        if sudo_match:
                            usuario, tty, pwd, usuario_destino, comando = sudo_match.groups()
                            hora_str_completa = hora.strftime("%Y-%m-%d %H:%M:%S")
                            lote_sudo.append((
                                usuario,
                                hora_str_completa,
                                tty,
                                pwd,
                                usuario_destino,
                                comando.strip(),
                                mensaje,
                                hora_str_completa
                            ))

                            if len(lote_sudo) >= tamaño_lote:
                                cursor.executemany(
                                    """
                                    INSERT INTO comandos_sudo (usuario, hora, tty, pwd, usuario_destino, comando, mensaje, timestamp)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                    """,
                                    lote_sudo
                                )
                                conn.commit()
                                logging.info("Insertados %d comandos sudo desde %s", len(lote_sudo), ruta_archivo)
                                print(f"Insertados {len(lote_sudo)} comandos sudo desde {ruta_archivo}")
                                lineas_procesadas += len(lote_sudo)
                                lote_sudo = []
                        else:
                            # Manejar otros mensajes relacionados con sudo
                            logging.warning("Formato de sudo no reconocido en %s línea %d: %s", ruta_archivo, numero_linea, mensaje)
                            cursor.execute(
                                """
                                INSERT INTO errores (archivo, numero_linea, contenido_linea, tiempo_inferido)
                                VALUES (?, ?, ?, ?)
                                """,
                                (ruta_archivo, numero_linea, f"Formato sudo no reconocido: {mensaje}", hora.strftime("%Y-%m-%d %H:%M:%S")),
                            )
                            continue
                else:
                    logging.warning("Formato de línea no coincidente en %s línea %d: %s", ruta_archivo, numero_linea, linea.strip())
                    cursor.execute(
                        """
                        INSERT INTO errores (archivo, numero_linea, contenido_linea, tiempo_inferido)
                        VALUES (?, ?, ?, ?)
                        """,
                        (ruta_archivo, numero_linea, "Formato de línea no coincidente", "N/A"),
                    )
                    continue
    except Exception as e:
        logging.error("Error al procesar el archivo secure %s en la línea %d: %s", ruta_archivo, numero_linea, e)
        sys.exit(1)
    finally:
        # Insertar cualquier lote restante
        if lote_auth:
            cursor.executemany(
                """
                INSERT INTO intentos_autenticacion (usuario, hora, servicio, ip, resultado, mensaje, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                lote_auth
            )
            conn.commit()
            logging.info("Insertados %d intentos de autenticación restantes desde %s", len(lote_auth), ruta_archivo)
            lineas_procesadas += len(lote_auth)

        if lote_sudo:
            cursor.executemany(
                """
                INSERT INTO comandos_sudo (usuario, hora, tty, pwd, usuario_destino, comando, mensaje, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                lote_sudo
            )
            conn.commit()
            logging.info("Insertados %d comandos sudo restantes desde %s", len(lote_sudo), ruta_archivo)
            lineas_procesadas += len(lote_sudo)

    return lineas_procesadas  # Retorna el número de líneas procesadas

def parsear_todos_secure(conn, archivos_mapeados, desde, hasta, tamaño_lote=5000):
    """
    Procesa todos los archivos 'secure' mapeados.
    Reporta el número de líneas por archivo y el total.
    Retorna el total de líneas de los archivos secure.
    """
    if not archivos_mapeados:
        print("No hay archivos secure para analizar dentro del rango de tiempo especificado.")
        logging.info("No hay archivos secure para analizar dentro del rango de tiempo especificado.")
        return 0

    total_lineas_secure = 0  # Contador total
    conteo_lineas_por_archivo = {}  # Diccionario para almacenar conteos por archivo

    print(f"\nSe encontraron {len(archivos_mapeados)} archivo(s) secure para analizar:")
    logging.info("Se encontraron %d archivo(s) secure para analizar.", len(archivos_mapeados))
    for info_archivo in archivos_mapeados:
        ruta_archivo, año, mes = info_archivo
        lineas = contar_lineas_secure(ruta_archivo)
        conteo_lineas_por_archivo[ruta_archivo] = lineas
        total_lineas_secure += lineas
        print(f" - {ruta_archivo}: {lineas} líneas")
        logging.info("Archivo secure a analizar: %s con %d líneas.", ruta_archivo, lineas)

    print(f"\nTotal de líneas de archivos secure: {total_lineas_secure}")
    logging.info("Total de líneas de archivos secure: %d", total_lineas_secure)

    # Ahora proceder a parsear los archivos secure
    for info_archivo in archivos_mapeados:
        ruta_archivo, año, mes = info_archivo
        logging.info("Parseando archivo secure: %s con año=%d, mes=%d", ruta_archivo, año, mes)
        print(f"\nParseando archivo secure: {ruta_archivo}")
        lineas_procesadas = parsear_unico_secure(ruta_archivo, conn, año, mes, desde, hasta, tamaño_lote)
        print(f"Finalizado el parseo del archivo secure: {ruta_archivo} con {lineas_procesadas} líneas procesadas.")
        logging.info("Finalizado el parseo del archivo secure: %s con %d líneas procesadas.", ruta_archivo, lineas_procesadas)

    return total_lineas_secure  # Retorna el total de líneas secure

def contar_lineas_secure(ruta_archivo):
    """
    Cuenta el número de líneas en un archivo 'secure'.
    Retorna el conteo de líneas.
    """
    abrir_func = gzip.open if ruta_archivo.endswith(".gz") else open
    modo = "rt"
    conteo = 0
    try:
        with abrir_func(ruta_archivo, modo, encoding="utf-8", errors="ignore") as f_in:
            for _ in f_in:
                conteo += 1
        logging.info("Contadas %d líneas en el archivo secure: %s", conteo, ruta_archivo)
    except Exception as e:
        logging.error("Error al contar líneas en el archivo secure %s: %s", ruta_archivo, e)
        print(f"Error al contar líneas en el archivo secure {ruta_archivo}: {e}")
    return conteo

def parsear_todos_wtmp(ruta, conn, desde, hasta, tamaño_lote=5000):
    """
    Encuentra y procesa todos los archivos 'wtmp' en el directorio especificado.
    Reporta el total de entradas procesadas.
    Retorna el total de entradas wtmp.
    """
    archivos_wtmp = glob.glob(os.path.join(ruta, "wtmp*"))
    if not archivos_wtmp:
        logging.warning("No se encontraron archivos wtmp en el directorio: %s", ruta)
        print("No se encontraron archivos wtmp en el directorio especificado.")
        return 0
    archivos_wtmp.sort()
    print(f"\nSe encontraron {len(archivos_wtmp)} archivo(s) wtmp para analizar:")
    logging.info("Se encontraron %d archivo(s) wtmp para analizar.", len(archivos_wtmp))
    for archivo in archivos_wtmp:
        print(f" - {archivo}")
        logging.info("Archivo wtmp a analizar: %s", archivo)
    total_entradas_wtmp = 0  # Contador total
    for archivo in archivos_wtmp:
        logging.info("Procesando archivo wtmp: %s", archivo)
        print(f"\nProcesando archivo wtmp: {archivo}")
        entradas = parsear_unico_wtmp(archivo, conn, desde, hasta, tamaño_lote)
        total_entradas_wtmp += entradas
        print(f"Finalizado el procesamiento del archivo wtmp: {archivo} con {entradas} entradas.")
        logging.info("Finalizado el procesamiento del archivo wtmp: %s con %d entradas.", archivo, entradas)
    print(f"\nTotal de entradas de archivos wtmp: {total_entradas_wtmp}")
    logging.info("Total de entradas de archivos wtmp: %d", total_entradas_wtmp)
    return total_entradas_wtmp  # Retorna el total de entradas

def parsear_unico_wtmp(ruta_archivo, conn, desde, hasta, tamaño_lote=5000):
    """
    Procesa un único archivo 'wtmp' y almacena las entradas relevantes dentro del rango de tiempo en la base de datos.
    Las entradas fuera del rango se registran en la tabla 'errores'.
    Retorna el número de entradas procesadas.
    """
    cursor = conn.cursor()
    lote = []
    numero_linea = 0
    entradas_procesadas = 0  # Contador de entradas

    try:
        for entrada in abrir_wtmp(ruta_archivo):
            numero_linea += 1
            if entrada['tipo'] == 'PROCESO_USUARIO' and entrada['timestamp']:
                timestamp = entrada['timestamp']
                if desde <= timestamp <= hasta:
                    timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    lote.append((entrada['usuario'], timestamp_str, entrada['terminal'], entrada['host'], timestamp_str))
                    entradas_procesadas += 1
                else:
                    logging.info("Entrada fuera del rango de tiempo en %s línea %d: %s", ruta_archivo, numero_linea, timestamp)
                    cursor.execute(
                        """
                        INSERT INTO errores (archivo, numero_linea, contenido_linea, tiempo_inferido)
                        VALUES (?, ?, ?, ?)
                        """,
                        (ruta_archivo, numero_linea, f"Entrada fuera del rango de tiempo: {timestamp}", timestamp.strftime("%Y-%m-%d %H:%M:%S")),
                    )
            # Insertar en lotes
            if len(lote) >= tamaño_lote:
                cursor.executemany(
                    """
                    INSERT INTO logins (usuario, hora, terminal, host, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    lote
                )
                conn.commit()
                logging.info("Insertadas %d entradas de logins desde %s", len(lote), ruta_archivo)
                print(f"Insertadas {len(lote)} entradas de logins desde {ruta_archivo}")
                lote = []
    except Exception as e:
        logging.error("Error al procesar el archivo wtmp %s en la línea %d: %s", ruta_archivo, numero_linea, e)
        sys.exit(1)
    finally:
        # Insertar cualquier entrada restante
        if lote:
            cursor.executemany(
                """
                INSERT INTO logins (usuario, hora, terminal, host, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                lote
            )
            conn.commit()
            logging.info("Insertadas %d entradas de logins restantes desde %s", len(lote), ruta_archivo)
            print(f"Insertadas {len(lote)} entradas de logins restantes desde {ruta_archivo}")

    return entradas_procesadas  # Retorna el número de entradas procesadas

# ================================
# Generación de Reportes
# ================================

def generar_graficos(conn, carpeta_salida, desde, hasta):
    """
    Genera gráficos basados en los datos agregados en la base de datos y los guarda en la carpeta de salida.
    También identifica los 10 días con mayor actividad para ciertos gráficos.
    Retorna un diccionario de títulos de gráficos a rutas de archivos y un diccionario de los top 10 días.
    """
    rutas_graficos = {}
    top10_dias = {}
    cursor = conn.cursor()

    # 1. Actividad de Inicios de Sesión por Mes
    print("\nGenerando Gráfico de Actividad de Inicios de Sesión por Mes...")
    logging.info("Generando Gráfico de Actividad de Inicios de Sesión por Mes.")
    cursor.execute("""
        SELECT strftime('%Y-%m', timestamp) as mes, COUNT(*) as conteo 
        FROM logins 
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY mes 
        ORDER BY mes
    """, (desde.strftime("%Y-%m-%d %H:%M:%S"), hasta.strftime("%Y-%m-%d %H:%M:%S")))
    conteos_login = cursor.fetchall()
    meses = [fila[0] for fila in conteos_login]
    conteos = [fila[1] for fila in conteos_login]

    if meses and conteos:
        plt.figure(figsize=(12, 6))
        plt.bar(meses, conteos, color='skyblue')
        plt.xlabel('Mes')
        plt.ylabel('Número de Inicios de Sesión')
        plt.title('Actividad de Inicios de Sesión por Mes')
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        ruta_grafico = os.path.join(carpeta_salida, 'grafico_actividad_login.png')
        plt.savefig(ruta_grafico)
        plt.close()
        rutas_graficos['Actividad de Inicios de Sesión'] = ruta_grafico
        logging.info("Gráfico generado: %s", ruta_grafico)
        print("Gráfico de Actividad de Inicios de Sesión generado.")
    else:
        logging.warning("No hay datos disponibles para el Gráfico de Actividad de Inicios de Sesión.")
        print("No hay datos disponibles para el Gráfico de Actividad de Inicios de Sesión.")

    # 2. Intentos de Autenticación por Mes
    print("\nGenerando Gráfico de Intentos de Autenticación por Mes...")
    logging.info("Generando Gráfico de Intentos de Autenticación por Mes.")
    cursor.execute("""
        SELECT strftime('%Y-%m', timestamp) as mes, COUNT(*) as conteo 
        FROM intentos_autenticacion 
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY mes 
        ORDER BY mes
    """, (desde.strftime("%Y-%m-%d %H:%M:%S"), hasta.strftime("%Y-%m-%d %H:%M:%S")))
    conteos_auth = cursor.fetchall()
    meses_auth = [fila[0] for fila in conteos_auth]
    conteos_auth_total = [fila[1] for fila in conteos_auth]

    if meses_auth and conteos_auth_total:
        plt.figure(figsize=(12, 6))
        plt.bar(meses_auth, conteos_auth_total, color='salmon')
        plt.xlabel('Mes')
        plt.ylabel('Intentos de Autenticación')
        plt.title('Intentos de Autenticación por Mes')
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        ruta_grafico = os.path.join(carpeta_salida, 'grafico_intentos_auth.png')
        plt.savefig(ruta_grafico)
        plt.close()
        rutas_graficos['Intentos de Autenticación'] = ruta_grafico
        logging.info("Gráfico generado: %s", ruta_grafico)
        print("Gráfico de Intentos de Autenticación generado.")
    else:
        logging.warning("No hay datos disponibles para el Gráfico de Intentos de Autenticación.")
        print("No hay datos disponibles para el Gráfico de Intentos de Autenticación.")

    # 3. Gráfico de Resultados de Autenticación (Pastel)
    print("\nGenerando Gráfico de Resultados de Autenticación (Pastel)...")
    logging.info("Generando Gráfico de Resultados de Autenticación (Pastel).")
    cursor.execute("""
        SELECT resultado, COUNT(*) as conteo 
        FROM intentos_autenticacion 
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY resultado
    """, (desde.strftime("%Y-%m-%d %H:%M:%S"), hasta.strftime("%Y-%m-%d %H:%M:%S")))
    conteos_resultados = cursor.fetchall()
    etiquetas = [fila[0] for fila in conteos_resultados]
    tamaños = [fila[1] for fila in conteos_resultados]

    if etiquetas and tamaños:
        plt.figure(figsize=(8, 8))
        plt.pie(tamaños, labels=etiquetas, autopct='%1.1f%%', startangle=140, colors=['lightgreen', 'lightcoral'])
        plt.title('Resultados de Intentos de Autenticación: Aceptados vs Fallidos')
        plt.axis('equal')
        plt.tight_layout()
        ruta_grafico = os.path.join(carpeta_salida, 'grafico_resultados_auth.png')
        plt.savefig(ruta_grafico)
        plt.close()
        rutas_graficos['Resultados de Autenticación'] = ruta_grafico
        logging.info("Gráfico generado: %s", ruta_grafico)
        print("Gráfico de Resultados de Autenticación generado.")
    else:
        logging.warning("No hay datos disponibles para el Gráfico de Resultados de Autenticación.")
        print("No hay datos disponibles para el Gráfico de Resultados de Autenticación.")

    # 4. Comandos Sudo por Mes
    print("\nGenerando Gráfico de Comandos Sudo por Mes...")
    logging.info("Generando Gráfico de Comandos Sudo por Mes.")
    cursor.execute("""
        SELECT strftime('%Y-%m', timestamp) as mes, COUNT(*) as conteo 
        FROM comandos_sudo 
        WHERE timestamp BETWEEN ? AND ?
        GROUP BY mes 
        ORDER BY mes
    """, (desde.strftime("%Y-%m-%d %H:%M:%S"), hasta.strftime("%Y-%m-%d %H:%M:%S")))
    conteos_sudo = cursor.fetchall()
    meses_sudo = [fila[0] for fila in conteos_sudo]
    conteos_sudo_total = [fila[1] for fila in conteos_sudo]

    if meses_sudo and conteos_sudo_total:
        plt.figure(figsize=(12, 6))
        plt.bar(meses_sudo, conteos_sudo_total, color='lightgreen')
        plt.xlabel('Mes')
        plt.ylabel('Comandos Sudo Ejecutados')
        plt.title('Comandos Sudo por Mes')
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        ruta_grafico = os.path.join(carpeta_salida, 'grafico_comandos_sudo.png')
        plt.savefig(ruta_grafico)
        plt.close()
        rutas_graficos['Comandos Sudo'] = ruta_grafico
        logging.info("Gráfico generado: %s", ruta_grafico)
        print("Gráfico de Comandos Sudo generado.")
    else:
        logging.warning("No hay datos disponibles para el Gráfico de Comandos Sudo.")
        print("No hay datos disponibles para el Gráfico de Comandos Sudo.")

    # 5. Top 10 Comandos Sudo
    print("\nGenerando Gráfico de Top 10 Comandos Sudo...")
    logging.info("Generando Gráfico de Top 10 Comandos Sudo.")
    cursor.execute("""
        SELECT comando, COUNT(*) as conteo 
        FROM comandos_sudo 
        GROUP BY comando 
        ORDER BY conteo DESC 
        LIMIT 10
    """)
    top_comandos_sudo = cursor.fetchall()
    if top_comandos_sudo:
        comandos = [fila[0] for fila in top_comandos_sudo]
        conteos = [fila[1] for fila in top_comandos_sudo]
        plt.figure(figsize=(12, 6))
        plt.barh(comandos[::-1], conteos[::-1], color='purple')
        plt.xlabel('Frecuencia')
        plt.ylabel('Comando Sudo')
        plt.title('Top 10 Comandos Sudo Más Frecuentes')
        plt.tight_layout()
        ruta_grafico = os.path.join(carpeta_salida, 'grafico_top10_comandos_sudo.png')
        plt.savefig(ruta_grafico)
        plt.close()
        rutas_graficos['Top 10 Comandos Sudo'] = ruta_grafico
        logging.info("Gráfico generado: %s", ruta_grafico)
        print("Gráfico de Top 10 Comandos Sudo generado.")
    else:
        logging.warning("No hay datos disponibles para el Gráfico de Top 10 Comandos Sudo.")
        print("No hay datos disponibles para el Gráfico de Top 10 Comandos Sudo.")

    # 6. Línea de Tiempo de Inicios de Sesión
    print("\nGenerando Gráfico de Línea de Tiempo de Inicios de Sesión...")
    logging.info("Generando Gráfico de Línea de Tiempo de Inicios de Sesión.")
    cursor.execute("""
        SELECT timestamp FROM logins 
        WHERE timestamp BETWEEN ? AND ?
        ORDER BY timestamp
    """, (desde.strftime("%Y-%m-%d %H:%M:%S"), hasta.strftime("%Y-%m-%d %H:%M:%S")))
    entradas_login = cursor.fetchall()

    if entradas_login:
        fechas_login = [datetime.strptime(fila[0], "%Y-%m-%d %H:%M:%S").date() for fila in entradas_login]
        conteo_fechas = Counter(fechas_login)
        fechas = sorted(conteo_fechas.keys())
        conteos = [conteo_fechas[fecha] for fecha in fechas]

        plt.figure(figsize=(14, 6))
        plt.plot(fechas, conteos, marker='o', linestyle='-', color='blue')
        plt.xlabel('Fecha')
        plt.ylabel('Número de Inicios de Sesión')
        plt.title('Tendencia de Inicios de Sesión en el Tiempo')
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        ruta_grafico = os.path.join(carpeta_salida, 'grafico_tiempo_login.png')
        plt.savefig(ruta_grafico)
        plt.close()
        rutas_graficos['Línea de Tiempo de Inicios de Sesión'] = ruta_grafico
        logging.info("Gráfico generado: %s", ruta_grafico)
        print("Gráfico de Línea de Tiempo de Inicios de Sesión generado.")

        # Top 10 días con mayor actividad
        top10_dias = conteo_fechas.most_common(10)
        top10_dias_formateados = {"Línea de Tiempo de Inicios de Sesión": [(dia.strftime("%Y-%m-%d"), conteo) for dia, conteo in top10_dias]}
    else:
        logging.warning("No hay entradas de inicio de sesión disponibles para el Gráfico de Línea de Tiempo.")
        print("No hay datos disponibles para el Gráfico de Línea de Tiempo de Inicios de Sesión.")
        top10_dias_formateados = {}

    conn.commit()
    return rutas_graficos, top10_dias_formateados

def generar_resumen(conn, total_entradas_wtmp, total_lineas_secure):
    """
    Genera estadísticas resumidas desde la base de datos.
    Incluye totales y listas principales.
    """
    resumen = {}
    cursor = conn.cursor()

    # Total inicios de sesión
    cursor.execute("SELECT COUNT(*) FROM logins")
    resumen["total_inicios"] = cursor.fetchone()[0]

    # Usuarios únicos
    cursor.execute("SELECT COUNT(DISTINCT usuario) FROM logins")
    resumen["usuarios_unicos"] = cursor.fetchone()[0]

    # Top usuarios activos
    cursor.execute(
        "SELECT usuario, COUNT(*) as conteo FROM logins GROUP BY usuario ORDER BY conteo DESC LIMIT 5"
    )
    resumen["top_usuarios"] = cursor.fetchall()

    # Top IPs con intentos de autenticación fallidos
    cursor.execute(
        'SELECT ip, COUNT(*) as conteo FROM intentos_autenticacion WHERE resultado = "Fallido" GROUP BY ip ORDER BY conteo DESC LIMIT 5'
    )
    resumen["top_ips_fallidos"] = cursor.fetchall()

    # Total comandos sudo
    cursor.execute("SELECT COUNT(*) FROM comandos_sudo")
    resumen["total_comandos_sudo"] = cursor.fetchone()[0]

    # Top comandos sudo
    cursor.execute(
        "SELECT comando, COUNT(*) as conteo FROM comandos_sudo GROUP BY comando ORDER BY conteo DESC LIMIT 10"
    )
    resumen["top_comandos_sudo"] = cursor.fetchall()

    # Comandos sudo únicos
    cursor.execute("SELECT COUNT(DISTINCT comando) FROM comandos_sudo")
    resumen["comandos_sudo_unicos"] = cursor.fetchone()[0]

    # Añadir totales de líneas procesadas
    resumen["total_entradas_wtmp"] = total_entradas_wtmp
    resumen["total_lineas_secure"] = total_lineas_secure

    conn.commit()
    logging.info("Generado resumen de estadísticas.")
    return resumen

def generar_reporte_principal(resumen, rutas_graficos, top10_dias, carpeta_salida, meses):
    """
    Genera el reporte principal en formato HTML y lo prepara para conversión a PDF.
    Incluye tablas con los top 10 días debajo de cada correspondiente gráfico.
    """
    # Estilos CSS
    estilos_css = """
    body { font-family: Arial, sans-serif; margin: 20px; }
    .grafico { margin-bottom: 50px; }
    .resumen { margin-bottom: 50px; }
    .resumen h2 { margin-top: 0; }
    ul { list-style-type: none; padding: 0; }
    li { margin: 5px 0; }
    a { text-decoration: none; color: #1a0dab; }
    a:hover { text-decoration: underline; }
    img { max-width: 100%; height: auto; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; table-layout: fixed; word-wrap: break-word; }
    th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; vertical-align: top; }
    th { background-color: #f2f2f2; }
    """

    # Estilos adicionales para versión PDF
    estilos_pdf = """
    @page {
        size: A4;
        margin: 20mm;
    }
    h1, h2, h3, h4, h5, h6 {
        page-break-after: avoid;
    }
    table, pre, img {
        page-break-inside: avoid;
    }
    """

    # Contenido HTML del reporte principal
    contenido_html = f"""
    <html>
    <head>
        <title>Reporte de Logs del Sistema</title>
        <style>
            {estilos_css}
        </style>
    </head>
    <body>
        <h1>Reporte de Logs del Sistema</h1>

        <div class="resumen">
            <h2>Estadísticas Resumidas</h2>
            <p><strong>Total de Inicios de Sesión:</strong> {resumen['total_inicios']}</p>
            <p><strong>Usuarios Únicos:</strong> {resumen['usuarios_unicos']}</p>
            <p><strong>Top Usuarios Activos:</strong></p>
            <ul>
    """

    for usuario, conteo in resumen["top_usuarios"]:
        contenido_html += f"<li>{usuario}: {conteo} inicios</li>\n"

    contenido_html += f"""
            </ul>
            <p><strong>Total de Comandos Sudo Ejecutados:</strong> {resumen['total_comandos_sudo']}</p>
            <p><strong>Comandos Sudo Únicos:</strong> {resumen['comandos_sudo_unicos']}</p>
            <p><strong>Top Comandos Sudo:</strong></p>
            <ul>
    """

    for comando, conteo in resumen["top_comandos_sudo"]:
        porcentaje = (
            (conteo / resumen["total_comandos_sudo"]) * 100
            if resumen["total_comandos_sudo"] > 0
            else 0
        )
        contenido_html += f"<li>{comando}: {conteo} veces ({porcentaje:.2f}%)</li>\n"

    contenido_html += f"""
            </ul>
            <p><strong>Top IPs con Intentos de Autenticación Fallidos:</strong></p>
            <ul>
    """

    for ip, conteo in resumen["top_ips_fallidos"]:
        contenido_html += f"<li>{ip}: {conteo} intentos</li>\n"

    # Añadir resumen de líneas procesadas
    contenido_html += f"""
            </ul>
            <h2>Resumen de Líneas Procesadas</h2>
            <p><strong>Total de Entradas de Archivos wtmp:</strong> {resumen['total_entradas_wtmp']}</p>
            <p><strong>Total de Líneas de Archivos secure:</strong> {resumen['total_lineas_secure']}</p>
        </div>
    """

    # Añadir gráficos y tablas de los top 10 días
    for titulo_grafico, ruta_grafico in rutas_graficos.items():
        contenido_html += f"""
    <div class="grafico">
        <h2>{titulo_grafico}</h2>
        <img src="{os.path.basename(ruta_grafico)}" alt="{titulo_grafico}">
    """
        if titulo_grafico in top10_dias:
            contenido_html += f"""
        <h3>Top 10 Días con Mayor Actividad</h3>
        <table>
            <thead>
                <tr>
                    <th>Fecha</th>
                    <th>Conteo</th>
                </tr>
            </thead>
            <tbody>
            """
            for dia, conteo in top10_dias[titulo_grafico]:
                contenido_html += f"""
                <tr>
                    <td>{dia}</td>
                    <td>{conteo}</td>
                </tr>
                """
            contenido_html += """
            </tbody>
        </table>
            """
        contenido_html += """
    </div>
        """

    # Añadir enlaces a reportes mensuales
    contenido_html += """
        <h2>Reportes Mensuales</h2>
        <ul>
    """

    for mes in meses:
        contenido_html += (
            f'<li><a href="reporte_{mes}.html">Reporte para {mes}</a></li>\n'
        )

    contenido_html += """
        </ul>
    </body>
    </html>
    """

    # Guardar la versión web del reporte principal
    ruta_html = os.path.join(carpeta_salida, "index.html")
    with open(ruta_html, "w", encoding="utf-8") as f:
        f.write(contenido_html)

    logging.info("Generado reporte HTML principal en %s", ruta_html)
    print(f"\nReporte HTML principal generado en {ruta_html}")
    logging.info("Generado reporte HTML principal en %s", ruta_html)

    # Preparar HTML para conversión a PDF
    contenido_html_pdf = f"""
    <html>
    <head>
        <title>Reporte de Logs del Sistema</title>
        <style>
            {estilos_css}
            {estilos_pdf}
        </style>
    </head>
    <body>
    """ + contenido_html.split("<body>")[1]

    # Guardar la versión HTML para PDF
    ruta_html_pdf = os.path.join(carpeta_salida, "index_pdf.html")
    with open(ruta_html_pdf, "w", encoding="utf-8") as f:
        f.write(contenido_html_pdf)

    return ruta_html_pdf  # Retorna la ruta del HTML para PDF

def generar_reportes_mensuales(conn, carpeta_salida, desde, hasta):
    """
    Genera reportes mensuales en formatos HTML y PDF.
    Solo incluye datos dentro del rango de fechas especificado.
    Retorna la lista de meses procesados.
    """
    cursor = conn.cursor()
    # Recuperar meses distintos de logins, intentos_autenticacion y comandos_sudo
    cursor.execute("""
        SELECT DISTINCT strftime('%Y-%m', timestamp) FROM logins
        WHERE timestamp BETWEEN ? AND ?
        UNION
        SELECT DISTINCT strftime('%Y-%m', timestamp) FROM intentos_autenticacion
        WHERE timestamp BETWEEN ? AND ?
        UNION
        SELECT DISTINCT strftime('%Y-%m', timestamp) FROM comandos_sudo
        WHERE timestamp BETWEEN ? AND ?
        ORDER BY 1
    """, (
        desde.strftime("%Y-%m-%d %H:%M:%S"),
        hasta.strftime("%Y-%m-%d %H:%M:%S"),
        desde.strftime("%Y-%m-%d %H:%M:%S"),
        hasta.strftime("%Y-%m-%d %H:%M:%S"),
        desde.strftime("%Y-%m-%d %H:%M:%S"),
        hasta.strftime("%Y-%m-%d %H:%M:%S"),
    ))
    meses = [fila[0] for fila in cursor.fetchall()]

    if not meses:
        print("\nNo hay datos mensuales disponibles para generar reportes.")
        logging.info("No hay datos mensuales disponibles para generar reportes.")
        return meses

    for mes in meses:
        logging.info("Generando reporte para %s", mes)
        print(f"\nGenerando reporte para {mes}...")
        logging.info("Iniciando generación de reporte para %s", mes)

        # Recuperar inicios de sesión
        cursor.execute(
            """
            SELECT usuario, hora, terminal, host
            FROM logins
            WHERE strftime('%Y-%m', timestamp) = ?
            ORDER BY timestamp
            """,
            (mes,),
        )
        inicios = cursor.fetchall()

        # Recuperar intentos de autenticación
        cursor.execute(
            """
            SELECT resultado, usuario, hora, servicio, ip, mensaje
            FROM intentos_autenticacion
            WHERE strftime('%Y-%m', timestamp) = ?
            ORDER BY timestamp
            """,
            (mes,),
        )
        intentos_auth = cursor.fetchall()

        # Recuperar comandos sudo
        cursor.execute(
            """
            SELECT usuario, hora, tty, pwd, usuario_destino, comando, mensaje
            FROM comandos_sudo
            WHERE strftime('%Y-%m', timestamp) = ?
            ORDER BY timestamp
            """,
            (mes,),
        )
        comandos_sudo = cursor.fetchall()

        # Estilos CSS
        estilos_css = """
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; table-layout: fixed; word-wrap: break-word; }
        th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; vertical-align: top; }
        th { background-color: #f2f2f2; }
        img { max-width: 100%; height: auto; }
        .grafico { margin-bottom: 50px; }
        .resumen { margin-bottom: 50px; }
        .resumen h2 { margin-top: 0; }
        """

        # Estilos adicionales para versión PDF
        estilos_pdf = """
        @page {
            size: A4;
            margin: 20mm;
        }
        h1, h2, h3, h4, h5, h6 {
            page-break-after: avoid;
        }
        table, pre, img {
            page-break-inside: avoid;
        }
        """

        # Contenido HTML del reporte mensual
        contenido_html = f"""
        <html>
        <head>
            <title>Reporte para {mes}</title>
            <style>
                {estilos_css}
            </style>
        </head>
        <body>
            <h1>Reporte para {mes}</h1>
        """

        # Añadir detalles de inicios de sesión
        contenido_html += """
            <h2>Detalles de Inicios de Sesión</h2>
            <table>
                <thead>
                    <tr>
                        <th>Usuario</th>
                        <th>Hora</th>
                        <th>Terminal</th>
                        <th>Host</th>
                    </tr>
                </thead>
                <tbody>
        """

        for entrada in inicios:
            usuario, hora, terminal, host = entrada
            contenido_html += f"""
                    <tr>
                        <td>{usuario}</td>
                        <td>{hora}</td>
                        <td>{terminal}</td>
                        <td>{host}</td>
                    </tr>
            """

        contenido_html += """
                </tbody>
            </table>
        """

        # Añadir intentos de autenticación
        contenido_html += """
            <h2>Intentos de Autenticación</h2>
            <table>
                <thead>
                    <tr>
                        <th>Resultado</th>
                        <th>Usuario</th>
                        <th>Hora</th>
                        <th>Servicio</th>
                        <th>IP</th>
                        <th>Mensaje</th>
                    </tr>
                </thead>
                <tbody>
        """

        for intento in intentos_auth:
            resultado, usuario, hora, servicio, ip, mensaje = intento
            contenido_html += f"""
                    <tr>
                        <td>{resultado}</td>
                        <td>{usuario}</td>
                        <td>{hora}</td>
                        <td>{servicio}</td>
                        <td>{ip}</td>
                        <td>{mensaje}</td>
                    </tr>
            """

        contenido_html += """
                </tbody>
            </table>
        """

        # Añadir comandos sudo
        contenido_html += """
            <h2>Comandos Sudo</h2>
            <table>
                <thead>
                    <tr>
                        <th>Usuario</th>
                        <th>Hora</th>
                        <th>TTY</th>
                        <th>PWD</th>
                        <th>Usuario Destino</th>
                        <th>Comando</th>
                        <th>Mensaje</th>
                    </tr>
                </thead>
                <tbody>
        """

        for comando in comandos_sudo:
            usuario, hora, tty, pwd, usuario_destino, comando_ejecutado, mensaje = comando
            contenido_html += f"""
                    <tr>
                        <td>{usuario}</td>
                        <td>{hora}</td>
                        <td>{tty}</td>
                        <td>{pwd}</td>
                        <td>{usuario_destino}</td>
                        <td>{comando_ejecutado}</td>
                        <td>{mensaje}</td>
                    </tr>
            """

        contenido_html += """
                </tbody>
            </table>
            <p><a href="index.html">Volver al Reporte Principal</a></p>
        </body>
        </html>
        """

        # Guardar la versión web del reporte mensual
        ruta_html = os.path.join(carpeta_salida, f"reporte_{mes}.html")
        with open(ruta_html, "w", encoding="utf-8") as f:
            f.write(contenido_html)

        logging.info("Generado reporte HTML para %s en %s", mes, ruta_html)
        print(f"Reporte HTML para {mes} generado en {ruta_html}")
        logging.info("Generado reporte HTML para %s en %s", mes, ruta_html)

        # Preparar HTML para conversión a PDF
        contenido_html_pdf = f"""
        <html>
        <head>
            <title>Reporte para {mes}</title>
            <style>
                {estilos_css}
                {estilos_pdf}
            </style>
        </head>
        <body>
        """ + contenido_html.split("<body>")[1]

        # Guardar la versión HTML para PDF
        ruta_html_pdf = os.path.join(carpeta_salida, f"reporte_{mes}_pdf.html")
        with open(ruta_html_pdf, "w", encoding="utf-8") as f:
            f.write(contenido_html_pdf)

        # Convertir HTML a PDF usando WeasyPrint
        ruta_pdf = os.path.join(carpeta_salida, f"reporte_{mes}.pdf")
        try:
            HTML(ruta_html_pdf, base_url=carpeta_salida).write_pdf(ruta_pdf)
            logging.info("Generado reporte PDF para %s en %s", mes, ruta_pdf)
            print(f"Reporte PDF para {mes} generado en {ruta_pdf}")
        except Exception as e:
            logging.error("Error al generar PDF para %s: %s", mes, e)
            print(f"Error al generar PDF para {mes}: {e}")

def generar_reportes_mensuales(conn, carpeta_salida, desde, hasta):
    """
    Genera reportes mensuales en formatos HTML y PDF.
    Solo incluye datos dentro del rango de fechas especificado.
    Retorna la lista de meses procesados.
    """
    cursor = conn.cursor()
    # Recuperar meses distintos de logins, intentos_autenticacion y comandos_sudo
    cursor.execute("""
        SELECT DISTINCT strftime('%Y-%m', timestamp) FROM logins
        WHERE timestamp BETWEEN ? AND ?
        UNION
        SELECT DISTINCT strftime('%Y-%m', timestamp) FROM intentos_autenticacion
        WHERE timestamp BETWEEN ? AND ?
        UNION
        SELECT DISTINCT strftime('%Y-%m', timestamp) FROM comandos_sudo
        WHERE timestamp BETWEEN ? AND ?
        ORDER BY 1
    """, (
        desde.strftime("%Y-%m-%d %H:%M:%S"),
        hasta.strftime("%Y-%m-%d %H:%M:%S"),
        desde.strftime("%Y-%m-%d %H:%M:%S"),
        hasta.strftime("%Y-%m-%d %H:%M:%S"),
        desde.strftime("%Y-%m-%d %H:%M:%S"),
        hasta.strftime("%Y-%m-%d %H:%M:%S"),
    ))
    meses = [fila[0] for fila in cursor.fetchall()]

    if not meses:
        print("\nNo hay datos mensuales disponibles para generar reportes.")
        logging.info("No hay datos mensuales disponibles para generar reportes.")
        return meses  # Retorna una lista vacía

    for mes in meses:
        logging.info("Generando reporte para %s", mes)
        print(f"\nGenerando reporte para {mes}...")
        logging.info("Iniciando generación de reporte para %s", mes)

        # Recuperar inicios de sesión
        cursor.execute(
            """
            SELECT usuario, hora, terminal, host
            FROM logins
            WHERE strftime('%Y-%m', timestamp) = ?
            ORDER BY timestamp
            """,
            (mes,),
        )
        inicios = cursor.fetchall()

        # Recuperar intentos de autenticación
        cursor.execute(
            """
            SELECT resultado, usuario, hora, servicio, ip, mensaje
            FROM intentos_autenticacion
            WHERE strftime('%Y-%m', timestamp) = ?
            ORDER BY timestamp
            """,
            (mes,),
        )
        intentos_auth = cursor.fetchall()

        # Recuperar comandos sudo
        cursor.execute(
            """
            SELECT usuario, hora, tty, pwd, usuario_destino, comando, mensaje
            FROM comandos_sudo
            WHERE strftime('%Y-%m', timestamp) = ?
            ORDER BY timestamp
            """,
            (mes,),
        )
        comandos_sudo = cursor.fetchall()

        # Estilos CSS
        estilos_css = """
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; table-layout: fixed; word-wrap: break-word; }
        th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; vertical-align: top; }
        th { background-color: #f2f2f2; }
        img { max-width: 100%; height: auto; }
        .grafico { margin-bottom: 50px; }
        .resumen { margin-bottom: 50px; }
        .resumen h2 { margin-top: 0; }
        """

        # Estilos adicionales para versión PDF
        estilos_pdf = """
        @page {
            size: A4;
            margin: 20mm;
        }
        h1, h2, h3, h4, h5, h6 {
            page-break-after: avoid;
        }
        table, pre, img {
            page-break-inside: avoid;
        }
        """

        # Contenido HTML del reporte mensual
        contenido_html = f"""
        <html>
        <head>
            <title>Reporte para {mes}</title>
            <style>
                {estilos_css}
            </style>
        </head>
        <body>
            <h1>Reporte para {mes}</h1>
        """

        # Añadir detalles de inicios de sesión
        contenido_html += """
            <h2>Detalles de Inicios de Sesión</h2>
            <table>
                <thead>
                    <tr>
                        <th>Usuario</th>
                        <th>Hora</th>
                        <th>Terminal</th>
                        <th>Host</th>
                    </tr>
                </thead>
                <tbody>
        """

        for entrada in inicios:
            usuario, hora, terminal, host = entrada
            contenido_html += f"""
                    <tr>
                        <td>{usuario}</td>
                        <td>{hora}</td>
                        <td>{terminal}</td>
                        <td>{host}</td>
                    </tr>
            """

        contenido_html += """
                </tbody>
            </table>
        """

        # Añadir intentos de autenticación
        contenido_html += """
            <h2>Intentos de Autenticación</h2>
            <table>
                <thead>
                    <tr>
                        <th>Resultado</th>
                        <th>Usuario</th>
                        <th>Hora</th>
                        <th>Servicio</th>
                        <th>IP</th>
                        <th>Mensaje</th>
                    </tr>
                </thead>
                <tbody>
        """

        for intento in intentos_auth:
            resultado, usuario, hora, servicio, ip, mensaje = intento
            contenido_html += f"""
                    <tr>
                        <td>{resultado}</td>
                        <td>{usuario}</td>
                        <td>{hora}</td>
                        <td>{servicio}</td>
                        <td>{ip}</td>
                        <td>{mensaje}</td>
                    </tr>
            """

        contenido_html += """
                </tbody>
            </table>
        """

        # Añadir comandos sudo
        contenido_html += """
            <h2>Comandos Sudo</h2>
            <table>
                <thead>
                    <tr>
                        <th>Usuario</th>
                        <th>Hora</th>
                        <th>TTY</th>
                        <th>PWD</th>
                        <th>Usuario Destino</th>
                        <th>Comando</th>
                        <th>Mensaje</th>
                    </tr>
                </thead>
                <tbody>
        """

        for comando in comandos_sudo:
            usuario, hora, tty, pwd, usuario_destino, comando_ejecutado, mensaje = comando
            contenido_html += f"""
                    <tr>
                        <td>{usuario}</td>
                        <td>{hora}</td>
                        <td>{tty}</td>
                        <td>{pwd}</td>
                        <td>{usuario_destino}</td>
                        <td>{comando_ejecutado}</td>
                        <td>{mensaje}</td>
                    </tr>
            """

        contenido_html += """
                </tbody>
            </table>
            <p><a href="index.html">Volver al Reporte Principal</a></p>
        </body>
        </html>
        """

        # Guardar la versión web del reporte mensual
        ruta_html = os.path.join(carpeta_salida, f"reporte_{mes}.html")
        with open(ruta_html, "w", encoding="utf-8") as f:
            f.write(contenido_html)

        logging.info("Generado reporte HTML para %s en %s", mes, ruta_html)
        print(f"Reporte HTML para {mes} generado en {ruta_html}")
        logging.info("Generado reporte HTML para %s en %s", mes, ruta_html)

        # Preparar HTML para conversión a PDF
        contenido_html_pdf = f"""
        <html>
        <head>
            <title>Reporte para {mes}</title>
            <style>
                {estilos_css}
                {estilos_pdf}
            </style>
        </head>
        <body>
        """ + contenido_html.split("<body>")[1]

        # Guardar la versión HTML para PDF
        ruta_html_pdf = os.path.join(carpeta_salida, f"reporte_{mes}_pdf.html")
        with open(ruta_html_pdf, "w", encoding="utf-8") as f:
            f.write(contenido_html_pdf)

        # Convertir HTML a PDF usando WeasyPrint
        ruta_pdf = os.path.join(carpeta_salida, f"reporte_{mes}.pdf")
        try:
            HTML(ruta_html_pdf, base_url=carpeta_salida).write_pdf(ruta_pdf)
            logging.info("Generado reporte PDF para %s en %s", mes, ruta_pdf)
            print(f"Reporte PDF para {mes} generado en {ruta_pdf}")
        except Exception as e:
            logging.error("Error al generar PDF para %s: %s", mes, e)
            print(f"Error al generar PDF para {mes}: {e}")

    return meses  # Retorna la lista de meses procesados

def generar_reporte_de_errores(conn, carpeta_salida):
    """
    Genera un reporte de errores listando cualquier entrada de log que estuvo fuera de rango o malformada.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT archivo, numero_linea, contenido_linea, tiempo_inferido FROM errores ORDER BY id")
    errores = cursor.fetchall()
    if errores:
        ruta_error = os.path.join(carpeta_salida, "reporte_errores.txt")
        with open(ruta_error, "w", encoding="utf-8") as f:
            f.write("Entradas de Logs Fuera de Rango o Malformadas:\n\n")
            for error in errores:
                archivo, numero_linea, contenido_linea, tiempo_inferido = error
                f.write(f"Archivo: {archivo}\n")
                f.write(f"Número de Línea: {numero_linea}\n")
                f.write(f"Contenido de Línea: {contenido_linea}\n")
                f.write(f"Tiempo Inferido: {tiempo_inferido}\n\n")
        logging.info("Generado reporte de errores en %s", ruta_error)
        print(f"\nReporte de errores generado en {ruta_error}")
    else:
        logging.info("No se encontraron errores durante el procesamiento.")
        print("\nNo se encontraron errores durante el procesamiento.")

def generar_reporte_principal_pdf(ruta_html_pdf, carpeta_salida):
    """
    Convierte el reporte HTML principal a PDF usando WeasyPrint.
    """
    ruta_pdf = os.path.join(carpeta_salida, "reporte_principal.pdf")
    try:
        HTML(ruta_html_pdf, base_url=carpeta_salida).write_pdf(ruta_pdf)
        logging.info("Generado reporte PDF principal en %s", ruta_pdf)
        print(f"Reporte PDF principal generado en {ruta_pdf}")
    except Exception as e:
        logging.error("Error al generar PDF principal: %s", e)
        print(f"Error al generar PDF principal: {e}")

# ================================
# Función Principal
# ================================

def main():
    """
    Función principal para coordinar el procesamiento de logs y la generación de reportes.
    """
    # 1. Solicitar directorio de logs
    ruta_logs = solicitar_directorio_logs()

    # 2. Determinar rango de tiempo a partir de archivos wtmp
    antigua, reciente = determinar_rango_tiempo_wtmp(ruta_logs)

    # 3. Solicitar confirmación o ingresar rango de tiempo personalizado
    if antigua and reciente:
        desde, hasta = solicitar_rango_tiempo(antigua, reciente)
    else:
        # Solicitar rango de tiempo personalizado si no se pudo inferir
        desde, hasta = solicitar_rango_tiempo_personalizado()

    # 4. Crear carpeta de salida
    carpeta_salida = crear_carpeta_salida()

    # 5. Inicializar base de datos
    conn = inicializar_base_datos(carpeta_salida)
    print("Base de datos generada exitosamente.")
    logging.info("Base de datos generada exitosamente.")

    # 6. Procesar archivos wtmp y obtener total de entradas
    total_entradas_wtmp = parsear_todos_wtmp(ruta_logs, conn, desde, hasta)
    print("Finalizado el escaneo de archivos wtmp.")

    # 7. Mapear archivos secure al rango de tiempo
    archivos_mapeados_secure = mapear_archivos_secure(ruta_logs, desde, hasta)

    # 8. Contar y reportar líneas en archivos secure, luego parsearlos
    total_lineas_secure = parsear_todos_secure(conn, archivos_mapeados_secure, desde, hasta)
    print("Finalizado el escaneo de archivos secure.")

    # 9. Agregar y reportar totales de líneas procesadas
    print(f"\nResumen de Líneas Procesadas:")
    print(f" - Total de Entradas de Archivos wtmp: {total_entradas_wtmp}")
    print(f" - Total de Líneas de Archivos secure: {total_lineas_secure}")
    logging.info("Resumen de Líneas Procesadas: wtmp=%d, secure=%d", total_entradas_wtmp, total_lineas_secure)

    # 10. Generar gráficos y obtener top 10 días
    rutas_graficos, top10_dias = generar_graficos(conn, carpeta_salida, desde, hasta)
    print("Gráficos generados exitosamente.")

    # 11. Generar estadísticas resumidas
    resumen = generar_resumen(conn, total_entradas_wtmp, total_lineas_secure)
    print("Estadísticas resumidas generadas.")

    # 12. Generar reportes mensuales
    meses = generar_reportes_mensuales(conn, carpeta_salida, desde, hasta)
    if meses:
        print("Reportes mensuales generados exitosamente.")
    else:
        print("No hay reportes mensuales para generar.")

    # 13. Generar reporte principal en HTML y preparar para PDF
    ruta_html_pdf = generar_reporte_principal(resumen, rutas_graficos, top10_dias, carpeta_salida, meses)
    print("Reporte HTML principal generado.")

    # 14. Generar reporte principal en PDF
    generar_reporte_principal_pdf(ruta_html_pdf, carpeta_salida)

    # 15. Generar reporte de errores si existen
    generar_reporte_de_errores(conn, carpeta_salida)

    # 16. Cerrar conexión de base de datos
    conn.close()

    print("\nProcesamiento completado exitosamente.")
    logging.info("Procesamiento completado exitosamente.")

# ================================
# Punto de Entrada
# ================================

if __name__ == "__main__":
    main()
