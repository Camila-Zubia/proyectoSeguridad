import socket
import threading
import datetime

# ===========================
# CONFIGURACIÓN INICIAL
# CONTIENE LA IP DEL SERVIDOR Y EL PUERTO ADEMAS DE QUE OBTIENE LA FECHA Y HORA DONDE SE MANDÓ EL MENSAJE
# ===========================

IP_SERVIDOR = 'localhost'
PUERTO = 12345

def obtener_fecha_hora():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# ===========================
# CLIENTE TCP
# MANEJA LA CONEXIÓN CON EL SERVIDOR CUANDO SE USA EL PROTOCOLO TCP
# ===========================

def cliente_tcp():
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente.connect((IP_SERVIDOR, PUERTO))

        prompt_opcion = cliente.recv(1024).decode()
        print(prompt_opcion, end='')
        opcion = input()
        cliente.send(opcion.encode())

        if opcion == '1' or opcion == '2':
            # 2. Recibe el prompt para nombre
            prompt_nombre = cliente.recv(1024).decode()
            print(prompt_nombre, end='')
            nombre = input()
            cliente.send(nombre.encode())

            # 3. Recibe el prompt para contraseña
            prompt_pass = cliente.recv(1024).decode()
            print(prompt_pass, end='')
            contraseña = input()
            cliente.send(contraseña.encode())

            # 4. Recibe el mensaje de éxito/error (Bienvenido, Usuario no encontrado, etc.)
            respuesta_servidor = cliente.recv(1024).decode()
            print(respuesta_servidor)

            # Si el servidor no envía un mensaje de "Bienvenido", asume que hubo un error y termina
            if not ("Bienvenido" in respuesta_servidor or "exitoso" in respuesta_servidor):
                cliente.close()
                main()
                return  # Termina la ejecución si la autenticación falla

        else:
            # Opción inválida manejada por el servidor, recibir su mensaje final y terminar
            respuesta_servidor = cliente.recv(1024).decode()
            print(respuesta_servidor)
            cliente.close()
            main()
            return

        def recibir():
            while True:
                try:
                    datos = cliente.recv(1024).decode()
                    if not datos:
                        break
                    print(datos)
                except:
                    break

        hilo_recv = threading.Thread(target=recibir)
        hilo_recv.daemon = True
        hilo_recv.start()

        while True:
            mensaje = input()
            if mensaje.lower() == 'salir':
                cliente.send("__salir__".encode())
                break
            cliente.send(mensaje.encode())

    except Exception as e:
        print(f"Error en conexión TCP: {e}")
    finally:
        cliente.close()
        main()


# ===========================
# MENÚ PRINCIPAL
# MENU AL CONECTARSE AL SERVIDOR
# ===========================

def main():

    cliente_tcp()

if __name__ == "__main__":
    main()