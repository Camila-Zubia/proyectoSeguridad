import socket
import threading
import datetime

# =======================
# CONFIGURACIÓN
# ESTE BLOQUE DE CÓDIGO CONTIENE LA IP Y EL PUERTO ASÍ COMO UNA LISTA QUE CONTIENE LOS CLIENTES CONECTADOS AL SERVIDOR
# =======================
IP = 'localhost'
PUERTO = 12345
MAX_CLIENTES = 3

clientes_tcp = {}  # {nombre: (socket, direccion)}
clientes_udp = {}  # {direccion: nombre}
credenciales = {} # {"cam": "1234"}

# =======================
# FUNCIONES AUXILIARES
# EN ESTE BLOQUE DE CÓDIGO HAY 2 FUNCIONES: LA PRIMERA SE ENCARGA DE OBTENER LA FECHA Y HORA DEL SISTEMA Y FORMATEARLA
# Y LA SEGUNDA SE ENCARGA DE MANEJAR LA OPCIÓN DE MANDAR MENSAJE DESDE EL SERVIDOR CON LA OPCIÓN DE EXPLUIR ALGUN USUARIO
# =======================

def obtener_fecha_hora():
    ahora = datetime.datetime.now()
    return ahora.strftime('%Y-%m-%d %H:%M:%S')

def enviar_a_todos(mensaje, excluir_tcp=None, excluir_udp=None):
    """Envía mensaje a TODOS los clientes TCP y UDP, con opción de excluir alguno"""
    for usuario, (sock, _) in clientes_tcp.items():
        if usuario != excluir_tcp:
            try:
                sock.sendall(mensaje.encode())
            except:
                pass
    for addr, nombre in clientes_udp.items():
        if addr != excluir_udp:
            try:
                udp_socket.sendto(mensaje.encode(), addr)
            except:
                pass

# =======================
# TCP
# ESTE BLOQUE DE CÓDIGO CONTIENE DOS FUNCIONES: LA PRIMERA QUE SE ENCARGA DE LA MENSAJERIA DE LOS CLIENTES PUESTOS EN TCP DONDE SE RECIBE EL USUARIO, LO INGRESA Y
# ESPERA MAS MENSAJES 
# LA SEGUNDA SE ENCARGA DE ABRIR EL PUERTO Y ESCUCHAR LOS MENSAJES ENTRANTES
# =======================

def manejar_cliente_tcp(sock, direccion):
    nombre = None
    try:
        sock.send("Bienvenido! Elige una opción (1 = Login, 2 = Registrarse): ".encode())
        opcion = sock.recv(1024).decode().strip()

        if opcion == '2':
            sock.send("Ingresa tu nombre de usuario: ".encode())
            nombre = sock.recv(1024).decode().strip()
            if nombre in clientes_tcp or nombre in [n for n, (s,a) in clientes_tcp.items()]:
                sock.send("Este nombre ya está en uso o conectado. Conexión terminada.".encode())
                sock.close()
                return
            if nombre in credenciales:
                sock.send("Este usuario ya existe. Conexión terminada.".encode())
                sock.close()
                return

            sock.send("Ingresa tu contraseña: ".encode())
            contraseña = sock.recv(1024).decode().strip()

            if len(contraseña) < 4:
                sock.send("La contraseña debe tener al menos 4 caracteres. Conexión terminada.".encode())
                sock.close()
                return

            credenciales[nombre] = contraseña
            sock.send(f"Registro exitoso, ¡Bienvenido {nombre}!\n".encode())

        elif opcion == '1':  # Login
            sock.send("Ingresa tu nombre de usuario: ".encode())
            nombre = sock.recv(1024).decode().strip()

            if nombre in clientes_tcp or nombre in [n for n, (s, a) in clientes_tcp.items()]:
                sock.send("Este nombre ya está conectado. Conexión terminada.".encode())
                sock.close()
                return

            if nombre not in credenciales:
                sock.send("Usuario no encontrado. Conexión terminada.".encode())
                sock.close()
                return

            sock.send("Ingresa tu contraseña: ".encode())
            contraseña = sock.recv(1024).decode().strip()

            if credenciales.get(nombre) != contraseña:
                sock.send("Contraseña incorrecta. Conexión terminada.".encode())
                sock.close()
                return

            sock.send(f"Login exitoso, ¡Bienvenido {nombre}!\n".encode())

        else:  # Opción inválida
            sock.send("Opción inválida. Conexión terminada.".encode())
            sock.close()
            return

        clientes_tcp[nombre] = (sock, direccion)
        print(f"[{obtener_fecha_hora()}] {nombre} (TCP) conectado desde {direccion}")
        enviar_a_todos(f"[{obtener_fecha_hora()}] {nombre} se unió al chat (TCP)\n", excluir_tcp=nombre)

        while True:
            mensaje = sock.recv(1024).decode()
            if not mensaje:
                break
            if mensaje == "__salir__":
                break

            if mensaje.startswith('@'):
                partes = mensaje.split(' ', 1)
                if len(partes) == 2:
                    destino, contenido = partes
                    destino = destino[1:]
                    if destino in clientes_tcp:
                        clientes_tcp[destino][0].sendall(f"[{obtener_fecha_hora()}] [Privado] {nombre}: {contenido}\n".encode())
                    else:
                        sock.send(f"Usuario {destino} no encontrado.\n".encode())
                else:
                    sock.send("Formato incorrecto. Usa: @usuario mensaje\n".encode())
            else:
                mensaje_completo = f"[{obtener_fecha_hora()}] {nombre} (TCP): {mensaje}"
                print(mensaje_completo)
                enviar_a_todos(mensaje_completo, excluir_tcp=nombre)

    except Exception as e:
        print(f"Error con {direccion} (TCP): {e}")
    finally:
        sock.close()
        if nombre in clientes_tcp:
            del clientes_tcp[nombre]
            print(f"[{obtener_fecha_hora()}] {nombre} (TCP) desconectado.")
            enviar_a_todos(f"[{obtener_fecha_hora()}] {nombre} ha salido del chat (TCP).\n")


def servidor_tcp():
    server_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_tcp.bind((IP, PUERTO))
    server_tcp.listen(MAX_CLIENTES)
    print(f"[TCP] Escuchando en {IP}:{PUERTO}")

    while True:
        sock, addr = server_tcp.accept()
        if len(clientes_tcp) >= MAX_CLIENTES:
            sock.send("Servidor lleno. Intenta más tarde.".encode())
            sock.close()
            continue

        hilo = threading.Thread(target=manejar_cliente_tcp, args=(sock, addr))
        hilo.daemon = True
        hilo.start()

# =======================
# UDP
# ESTE BLOQUE DE CODIGO SE ENCARGA DE ABRIR EL PUERTO UDP PARA ESCUCHAR LOS MENSAJES QUE SE ENVÍAN DESDE ESTE PROTOCOLO
# =======================

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def servidor_udp():
    udp_socket.bind((IP, PUERTO))
    print(f"[UDP] Escuchando en {IP}:{PUERTO}")

    while True:
        try:
            data, addr = udp_socket.recvfrom(1024)
            mensaje = data.decode().strip()
            if mensaje == "__salir__":
                if addr in clientes_udp:
                    nombre = clientes_udp.pop(addr)
                    print(f"[{obtener_fecha_hora()}] {nombre} (UDP) desconectado.")
                    enviar_a_todos(f"[{obtener_fecha_hora()}] {nombre} ha salido del chat (UDP).", excluir_udp=addr)
                continue
            if addr not in clientes_udp:
                clientes_udp[addr] = mensaje
                bienvenida = f"{mensaje} (UDP) se unió al chat."
                print(f"[{obtener_fecha_hora()}] {bienvenida}")
                enviar_a_todos(f"[{obtener_fecha_hora()}] {bienvenida}", excluir_udp=addr)
                continue

            nombre = clientes_udp[addr]
            mensaje_completo = f"[{obtener_fecha_hora()}] {nombre} (UDP): {mensaje}"
            print(mensaje_completo)
            enviar_a_todos(mensaje_completo, excluir_udp=addr)

        except Exception as e:
            print(f"Error en UDP: {e}")

# =======================
# CONSOLA DEL SERVIDOR
# MANEJA LA ENTRADA DE MENSAJES DEL SERVIDOR PARA EVITAR UNA SOBREPOSICIÓN DE LOS MENSAJES 
# =======================

def consola_servidor():
    """Permite al servidor enviar mensajes a todos o a uno en específico"""
    print("Puedes escribir mensajes como servidor. Usa '@usuario mensaje' para mensaje privado y 'salir' para cerrar el chat.")
    while True:
        mensaje = input()
        if mensaje.lower() == 'salir':
            print("Servidor detenido.")
            exit(0)

        if mensaje.startswith('@'):
            partes = mensaje.split(' ', 1)
            if len(partes) == 2:
                destino = partes[0][1:]  # sin @
                contenido = partes[1]
                mensaje_privado = f"[{obtener_fecha_hora()}] [Privado del Servidor]: {contenido}"

                # Buscar en clientes TCP
                if destino in clientes_tcp:
                    try:
                        clientes_tcp[destino][0].sendall(mensaje_privado.encode())
                        print(f"✅ Mensaje privado enviado a {destino} (TCP)")
                    except:
                        print(f"❌ Error al enviar a {destino} (TCP)")
                    continue

                # Buscar en clientes UDP
                for addr, nombre in clientes_udp.items():
                    if nombre == destino:
                        try:
                            udp_socket.sendto(mensaje_privado.encode(), addr)
                            print(f"✅ Mensaje privado enviado a {destino} (UDP)")
                        except:
                            print(f"❌ Error al enviar a {destino} (UDP)")
                        break
                else:
                    print(f"⚠ Usuario '{destino}' no encontrado.")
            else:
                print("Formato incorrecto. Usa: @usuario mensaje")
        else:
            mensaje_servidor = f"[{obtener_fecha_hora()}] Servidor: {mensaje}"
            enviar_a_todos(mensaje_servidor)

# =======================
# INICIO
# MANEJA TODOS LOS HILOS
# =======================

if __name__ == "__main__":
    hilo_tcp = threading.Thread(target=servidor_tcp)
    hilo_udp = threading.Thread(target=servidor_udp)
    hilo_admin = threading.Thread(target=consola_servidor)

    hilo_tcp.daemon = True
    hilo_udp.daemon = True
    hilo_admin.daemon = True

    hilo_tcp.start()
    hilo_udp.start()
    hilo_admin.start()

    print("Servidor de chat listo. Esperando conexiones TCP y UDP...")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Servidor finalizado.")