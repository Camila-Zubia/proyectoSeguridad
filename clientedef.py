import socket
import threading
import datetime
import ssl

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
    contexto_ssl = ssl.create_default_context()
    try:
        contexto_ssl.load_verify_locations(cafile="server.pem")
    except FileNotFoundError:
        print("¡ERROR! No se encontró el archivo 'server.pem' para la validación.")
        return
    contexto_ssl.check_hostname = False
    contexto_ssl.verify_mode = ssl.CERT_REQUIRED
    cliente_normal = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente = None
    try:
        cliente_normal.connect((IP_SERVIDOR, PUERTO))
        cliente = contexto_ssl.wrap_socket(cliente_normal, server_hostname=IP_SERVIDOR)
        prompt_opcion = cliente.recv(1024).decode()
        print(prompt_opcion, end='')
        opcion = input()
        cliente.send(opcion.encode())

        if opcion == '1' or opcion == '2':
            prompt_nombre = cliente.recv(1024).decode()
            print(prompt_nombre, end='')
            nombre = input()
            cliente.send(nombre.encode())

            prompt_pass = cliente.recv(1024).decode()
            print(prompt_pass, end='')
            contraseña = input()
            cliente.send(contraseña.encode())

            respuesta_servidor = cliente.recv(1024).decode()
            print(respuesta_servidor)

            if not ("Bienvenido" in respuesta_servidor or "exitoso" in respuesta_servidor):
                cliente.close()
                return

        else:
            respuesta_servidor = cliente.recv(1024).decode()
            print(respuesta_servidor)
            cliente.close()
            return

        def recibir():
            while True:
                try:
                    datos = cliente.recv(1024).decode()
                    if not datos:
                        print("\nEl servidor ha cerrado la conexión.")
                        break
                    print(datos, end='')
                except (ConnectionResetError, ssl.SSLError, socket.error):
                    print("\nConexión perdida con el servidor.")
                    break
                except Exception as e:
                    print(f"\nError de recepción: {e}")
                    break

        hilo_recv = threading.Thread(target=recibir)
        hilo_recv.daemon = True
        hilo_recv.start()

        while True:
            mensaje = input()
            if mensaje.lower() == 'salir':
                cliente.send("__salir__".encode())
                break

            if not mensaje.strip():
                print("El mensaje no puede estar vacío.")
                continue
            cliente.send(mensaje.encode())

    except ssl.SSLError as e:
        print(f"Error SSL al conectar: {e}")
    except Exception as e:
        print(f"Error en conexión TCP: {e}")
    finally:
        if cliente:
            cliente.close()


# ===========================
# MENÚ PRINCIPAL
# MENU AL CONECTARSE AL SERVIDOR
# ===========================

def main():
    while True:
        print("\n--- Menú de Cliente ---")
        print("1. Conectar al Chat")
        print("2. Salir")

        choice = input("Elige una opción: ")

        if choice == '1':
            cliente_tcp()
        elif choice == '2':
            print("Saliendo del programa.")
            break
        else:
            print("Opción no válida. Intenta de nuevo.")

if __name__ == "__main__":
    main()