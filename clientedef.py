import socket
import threading
import datetime
import ssl
import getpass

# ===========================
# CONFIGURACIÓN INICIAL
# CONTIENE LA IP DEL SERVIDOR Y EL PUERTO ADEMAS DE QUE OBTIENE LA FECHA Y HORA DONDE SE MANDÓ EL MENSAJE
# ===========================

IP_SERVIDOR = 'localhost' 
PUERTO = 12345

def obtener_fecha_hora():
    """
Retorna la fecha y hora actual formateada como un string.
Se utiliza para logs o mensajes locales
    """
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# ===========================
# CLIENTE TCP
# MANEJA LA CONEXIÓN CON EL SERVIDOR CUANDO SE USA EL PROTOCOLO TCP
# ===========================

def cliente_tcp():
    """Crea un contexto SSL seguro utilizando el archivo server.pem, lo que verifica el 
       certificado del servidor
       Realiza el handshake de autenticacion entre el login y el registro
       Inicia un hilo para recibir mensajes y mantiene el hilo principal para enviarlos."""
    contexto_ssl = ssl.create_default_context()
    try:
        contexto_ssl.load_verify_locations(cafile="server.pem")
    except FileNotFoundError:
        print("¡ERROR! No se encontró el archivo 'server.pem' para la validación.")
        return
    contexto_ssl.check_hostname = False
    contexto_ssl.verify_mode = ssl.CERT_REQUIRED

    """A partir de aqui se conecta al servidor creando el socket y lo convierte a
       SSL con contexto_ssl.wrap_socket"""
    cliente_normal = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cliente = None
    try:
        # Conexion TCP
        cliente_normal.connect((IP_SERVIDOR, PUERTO))
        # Envuelve el socket TCP con SSL
        cliente = contexto_ssl.wrap_socket(cliente_normal, server_hostname=IP_SERVIDOR)
        # El usuario Recibe el menu inicio
        prompt_opcion = cliente.recv(1024).decode()
        print(prompt_opcion, end='')
        # El usuario Envia la opcion seleccionada
        opcion = input()
        cliente.send(opcion.encode())

        """Cuando el usuario se registre pero el servidor no de una respuesta exitosa, el cliente
           se va a desconectar"""
        if opcion == '1' or opcion == '2':
            #Envia el nombre de usuario
            prompt_nombre = cliente.recv(1024).decode()
            print(prompt_nombre, end='')
            nombre = input()
            nombre_sanitizado = nombre.strip()
            cliente.send(nombre_sanitizado.encode())

            prompt_pass_raw = cliente.recv(1024).decode()
            prompt_pass = prompt_pass_raw.strip()
            contraseña = getpass.getpass(prompt_pass + " ")
            contraseña_sanitizada = contraseña.strip()
            cliente.send(contraseña_sanitizada.encode())
            #Recibe el resultado de la autenticacion
            respuesta_servidor = cliente.recv(1024).decode()
            print(respuesta_servidor)
           #Si el servidor no confirma el exito cierra el cliente
            if not ("Bienvenido" in respuesta_servidor or "exitoso" in respuesta_servidor):
                cliente.close()
                return

        else:
            respuesta_servidor = cliente.recv(1024).decode()
            print(respuesta_servidor)
            cliente.close()
            return

        """Este metodo permite al cliente recibir los mensajes que vengan del servidor tanto de otros clientes
           como del mismo servidor"""
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

        """A partir de aqui están las lineas que permiten al cliente enviar mensajes en el servidor
           Se sanitizan los mensajes eliminando espacios vacios no relevantes"""
        while True:
            mensaje_entrada = input()
            mensaje_sanitizado = mensaje_entrada.strip()
            if mensaje_sanitizado.lower() == 'salir':
                cliente.send("__salir__".encode())
                break

            if not mensaje_sanitizado:
                print("El mensaje no puede estar vacío.")
                continue

            if mensaje_sanitizado.startswith('@'):
                partes = mensaje_sanitizado.split(' ', 1)
                if len(partes) < 2 or not partes[0][1:].strip() or not partes[1].strip():
                    print("Formato de mensaje privado incorrecto. Usa: @usuario mensaje_aqui")
                    continue

            cliente.send(mensaje_sanitizado.encode())

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
"""
Menu principal donde se muestran las opciones.
"""
    
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
