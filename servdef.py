import socket
import threading
import datetime
import ssl
import logging
import bcrypt
import json

# =======================
# CONFIGURACIÓN DEL LOGGING
# =======================
logging.basicConfig(
    filename='chat_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    filemode='a'
)
logger = logging.getLogger()

# =======================
# CONFIGURACIÓN DEL SERVIDOR
# =======================
IP = 'localhost'
PUERTO = 12345
MAX_CLIENTES = 2

# Diccionario para guardar la sesion de los usuarios
clientes_tcp = {}
ARCHIVO_CREDENCIALES = 'credenciales.json'
credenciales = {}

# =======================
# FUNCIONES AUXILIARES
# =======================

def obtener_fecha_hora():
    """Regresa la fecha y hora actual para estamparla en los mensajes del chat """
    ahora = datetime.datetime.now()
    return ahora.strftime('%Y-%m-%d %H:%M:%S')

def enviar_a_todos(mensaje, excluir_tcp=None):
    """Envía mensaje a TODOS los clientes TCP, con opción de excluir alguno
    :param mensaje: El texto a enviar
    :param excluir_tcp:Nombre del usuario a excluir. Nadie por defecto.
    """
    for usuario, (sock, _) in clientes_tcp.items():
        if usuario != excluir_tcp:
            try:
                sock.sendall(mensaje.encode())
            except:
                logger.warning(f"Error al enviar mensaje a {usuario}. Socket inválido.")
                pass

def cargar_credenciales():
    """Carga las credenciales desde el archivo credenciales.json"""
    global credenciales
    try:
        with open(ARCHIVO_CREDENCIALES, 'r') as f:
            credenciales = json.load(f)
            logger.info("Credenciales cargadas desde el archivo.")
    except FileNotFoundError:
        logger.warning("Archivo de credenciales no encontrado. Iniciando con diccionario vacío.")
    except json.JSONDecodeError:
        logger.error("Error al leer el archivo de credenciales. Asegúrate de que no esté corrupto.")

def guardar_credenciales():
    """Escribe el diccionario actual de credenciales en el archivo JSON."""
    try:
        with open(ARCHIVO_CREDENCIALES, 'w') as f:
            json.dump(credenciales, f)
            logger.info("Credenciales guardadas en el archivo.")
    except Exception as e:
        logger.error(f"Fallo al guardar credenciales: {e}")

# =======================
# MANEJO DE CLIENTES
# =======================

def manejar_cliente_tcp(sock_ssl, direccion):
    """Metodo que permite el manejo de los clientes, desde su registro, login y envío de mensajes"""
    """Esta primera sección está dedicada al login y registro de usuarios, garantizar una contraseña segura y
       un nombre de usuario unico"""
    global credenciales
    nombre = None
    try:
        sock_ssl.send("Bienvenido! Elige una opción (1 = Login, 2 = Registrarse): ".encode())
        opcion = sock_ssl.recv(1024).decode().strip()

        if opcion == '2':
            sock_ssl.send("Ingresa tu nombre de usuario: ".encode())
            nombre = sock_ssl.recv(1024).decode().strip()
         #Validaciones de nombre
            if not nombre.isalnum() or len(nombre) < 3:
                sock_ssl.send("Nombre inválido: solo alfanuméricos (mínimo 3 caracteres). Conexión terminada.".encode())
                sock_ssl.close()
                return

            if nombre in clientes_tcp:
                sock_ssl.send("Este nombre ya está conectado. Conexión terminada.".encode())
                sock_ssl.close()
                return
            if nombre in credenciales:
                sock_ssl.send("Este usuario ya existe. Conexión terminada.".encode())
                sock_ssl.close()
                return

            sock_ssl.send("Ingresa tu contraseña: ".encode())
            contraseña = sock_ssl.recv(1024).decode().strip()

            if len(contraseña) < 4:
                sock_ssl.send("La contraseña debe tener al menos 4 caracteres. Conexión terminada.".encode())
                sock_ssl.close()
                return
        #genera el hash de la contraseña
            contraseña_bytes = contraseña.encode('utf-8')
            hash_contraseña = bcrypt.hashpw(contraseña_bytes, bcrypt.gensalt()).decode('utf-8')
        #guarda las credencias del usuario
            credenciales[nombre] = hash_contraseña
            guardar_credenciales()
            logger.info(f"Nuevo usuario registrado: {nombre}")

            sock_ssl.send(f"Registro exitoso, ¡Bienvenido {nombre}!\n".encode())
        #Login
        elif opcion == '1':
            sock_ssl.send("Ingresa tu nombre de usuario: ".encode())
            nombre = sock_ssl.recv(1024).decode().strip()

            if nombre in clientes_tcp:
                sock_ssl.send("Este nombre ya está conectado. Conexión terminada.".encode())
                sock_ssl.close()
                return

            if nombre not in credenciales:
                sock_ssl.send("Usuario no encontrado. Conexión terminada.".encode())
                sock_ssl.close()
                return
  #Verificacion de contraseña correcta
            sock_ssl.send("Ingresa tu contraseña: ".encode())
            contraseña = sock_ssl.recv(1024).decode().strip()

            contraseña_ingresada_bytes = contraseña.encode('utf-8')
            hash_almacenado_bytes = credenciales.get(nombre).encode('utf-8')

            if not bcrypt.checkpw(contraseña_ingresada_bytes, hash_almacenado_bytes):
                sock_ssl.send("Contraseña incorrecta. Conexión terminada.".encode())
                sock_ssl.close()
                return

            sock_ssl.send(f"Login exitoso, ¡Bienvenido {nombre}!\n".encode())
            logger.info(f"Login exitoso para usuario: {nombre}")


        else:
            sock_ssl.send("Opción inválida. Conexión terminada.".encode())
            sock_ssl.close()
            logger.warning(f"Conexión de {direccion} terminó por opción inválida.")
            return
       #Seccion de Sesion activa
        clientes_tcp[nombre] = (sock_ssl, direccion)
        logger.info(f"Usuario {nombre} conectado desde {direccion}")
        print(f"[{obtener_fecha_hora()}] {nombre} (TCP) conectado desde {direccion}")
        enviar_a_todos(f"[{obtener_fecha_hora()}] {nombre} se unió al chat.\n", excluir_tcp=nombre)

        """Una vez el usuario se haya registrado, esta parte es exclusiva a los mensajes que manda"""
        while True:
            mensaje = sock_ssl.recv(1024).decode()
            if not mensaje:
                break
            if mensaje == "__salir__":
                break
                
          #Mensaje privado
            if mensaje.startswith('@'):
                partes = mensaje.split(' ', 1)
                if len(partes) == 2:
                    destino, contenido = partes
                    destino = destino[1:] #Quitar el '@'
                    mensaje_privado = f"[{obtener_fecha_hora()}] [Privado] {nombre}: {contenido}\n"
    #Busca el socket del destinatario
                    if destino in clientes_tcp:
                        clientes_tcp[destino][0].sendall(mensaje_privado.encode())
                        sock_ssl.send(f"Mensaje privado enviado a {destino}.\n".encode())
                        logger.info(f"Mensaje PRIVADO de {nombre} a {destino}: {contenido}")
                    else:
                        sock_ssl.send(f"Usuario {destino} no encontrado.\n".encode())
                        logger.warning(f"Intento de mensaje privado de {nombre} a usuario no encontrado: {destino}")
                else:
                    sock_ssl.send("Formato incorrecto. Usa: @usuario mensaje\n".encode())
                    logger.warning(f"Mensaje de {nombre} con formato privado incorrecto.")
     #Mensaje publico
            else:
                mensaje_completo = f"[{obtener_fecha_hora()}] {nombre}: {mensaje}\n"
                logger.info(f"Mensaje PUBLICO de {nombre}: {mensaje}")
                print(mensaje_completo)
                enviar_a_todos(mensaje_completo, excluir_tcp=nombre)

    except ssl.SSLError as e:
        logger.error(f"Error SSL con cliente {direccion}: {e}")
        print(f"Error con {direccion} (TCP): {e}")
    except Exception as e:
        logger.error(f"Error en manejo de cliente {direccion}: {e}")
    finally:
        # Limpia la desconectar
        if nombre in clientes_tcp:
            del clientes_tcp[nombre]
            logger.info(f"Usuario {nombre} desconectado.")
            print(f"[{obtener_fecha_hora()}] {nombre} (TCP) desconectado.")
            enviar_a_todos(f"[{obtener_fecha_hora()}] {nombre} ha salido del chat.\n")

        try:
            sock_ssl.close()
        except:
            pass


def servidor_tcp():
    """Inicializa el socket del servidor TCP, carga certificados y espera conexiones entrantes."""
    cargar_credenciales()
    #Se configura el contexto SSL para el lado del servidor
    contexto_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto_ssl.set_ciphers('DEFAULT')

    try:
        #Carga el par de claves Certificado y llave privada
        contexto_ssl.load_cert_chain(certfile="server.pem", keyfile="server.pem")
    except FileNotFoundError:
        print("¡ERROR! No se encontró el archivo 'server.pem'. Por favor, generarlo con OpenSSL.")
        logger.critical("No se encontró el archivo 'server.pem'. Servidor no iniciado.")
        return
   #Creacion del socket TPC
    server_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_tcp.bind((IP, PUERTO))
        server_tcp.listen(MAX_CLIENTES)
    except Exception as e:
        print(f"Error al iniciar el servidor: {e}")
        logger.critical(f"Fallo al iniciar el servidor en {IP}:{PUERTO}: {e}")
        return

    print(f"[TCP] Escuchando en {IP}:{PUERTO}")
    logger.info(f"Servidor TCP iniciado en {IP}:{PUERTO}. Máx clientes: {MAX_CLIENTES}")
 #Bucle para aceptar las conexiones.
    while True:
        sock, addr = server_tcp.accept()
     #Control de capacidad maxima.
        if len(clientes_tcp) >= MAX_CLIENTES:
            try:
                sock_ssl_temp = contexto_ssl.wrap_socket(sock, server_side=True)
                sock_ssl_temp.send("Servidor lleno. Intenta más tarde.".encode())
                sock_ssl_temp.close()
                logger.warning(f"Conexión rechazada de {addr}. Límite de {MAX_CLIENTES} alcanzado.")
            except:
                sock.close()
            continue

        try:
            #Envuelve cada socket entrante (usuario) con SSL
            sock_ssl = contexto_ssl.wrap_socket(sock, server_side=True)
            #delega la atencion del cliente a un hilo independiente
            hilo = threading.Thread(target=manejar_cliente_tcp, args=(sock_ssl, addr))
            hilo.daemon = True
            hilo.start()
        except ssl.SSLError as e:
            logger.error(f"Error SSL al establecer conexión con {addr}: {e}")
            sock.close()


# =======================
# CONSOLA DEL SERVIDOR
# =======================

def consola_servidor():
    """Permite al servidor enviar mensajes a todos los usuarios o a uno en específico"""
    """Tambien permite leer los mensajes tanto publicos y privados de los usuarios"""
    
    print("Puedes escribir mensajes como servidor. Usa '@usuario mensaje' para mensaje privado y 'salir' para cerrar el chat.")
    while True:
        try:
            mensaje = input()
        except EOFError:
            break
        except KeyboardInterrupt:
            break

        if mensaje.lower() == 'salir':
            print("Servidor detenido.")
            logger.critical("Servidor finalizado por comando 'salir' en consola.")
            exit(0) #Termina el programa

        if mensaje.startswith('@'):
            partes = mensaje.split(' ', 1)
            if len(partes) == 2:
                destino = partes[0][1:]
                contenido = partes[1]
                mensaje_privado = f"[{obtener_fecha_hora()}] [Privado del Servidor]: {contenido}"

                # Buscar en clientes TCP
                if destino in clientes_tcp:
                    try:
                        clientes_tcp[destino][0].sendall(mensaje_privado.encode())
                        print(f"Mensaje privado enviado a {destino}")
                        logger.info(f"Servidor envió mensaje PRIVADO a {destino}: {contenido}")
                    except:
                        print(f"Error al enviar a {destino}. Probablemente se desconectó.")
                        logger.warning(f"Error al enviar mensaje privado del Servidor a {destino}.")
                else:
                    print(f"Usuario '{destino}' no encontrado.")
            else:
                print("Formato incorrecto. Usa: @usuario mensaje")
        else:
            #Broadcast del servidor
            mensaje_servidor = f"[{obtener_fecha_hora()}] Servidor: {mensaje}\n"
            enviar_a_todos(mensaje_servidor)
            logger.info(f"Servidor envió mensaje PUBLICO: {mensaje}")


# =======================
# INICIO DEL SERVIDOR
# =======================

if __name__ == "__main__":
    # Hilo tcp: Escucha conexiones TCP entrantes
    hilo_tcp = threading.Thread(target=servidor_tcp)
    # Hilo admin: Maneja la consola del administrador 
    hilo_admin = threading.Thread(target=consola_servidor)
    #Asegura que si el hilo principal muere, estos tambien se cierren.
    hilo_tcp.daemon = True
    hilo_admin.daemon = True

    hilo_tcp.start()
    hilo_admin.start()

    print("Servidor de chat listo. Esperando conexiones TCP/SSL")

    try:
        # Mantiene el hilo vivo esperando señales
        while True:
            threading.Event().wait()
    except (KeyboardInterrupt, SystemExit):

        print("Servidor finalizado.")

