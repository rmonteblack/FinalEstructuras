from metodos import *
import sys


def menu():

    print()
    print()
    print("Bienvenido usuario, por favor ingrse una opción para continuar")
    print("1. Ingresar mensaje")
    print("2. Calcular hash FNV-1")
    print("3. Comprimir mensaje (RLE)")
    print("4. Firmar (hash con clave privada RSA)")
    print("5. Simular envío (mensaje comprimido + firma + clave pública)")
    print("6. Verificación de auntenticidad")
    print("7. Salir")
    print()
    print()


def main():


    #variables de estado (almacen de emisor)
    #guardan los datos entre pasos
    mensaje_original = None
    fnv1_hash = None
    mensaje_compreso = None
    clave_privada = None
    clave_publica = None
    firma = None

    #variable de  (simulación de "servidor/red")
    #simula el paquete que viaja del emisor al receptor
    paquete_enviado = None

    while True:
        menu()
        opcion = input("Seleccione una opción para continuar: ")


        if opcion == '1':
            mensaje_original = input("\n[Paso 1] Ingrese su mensaje: ")
            print(f"Mensaje guardado: '{mensaje_original}'")
            #reseteamos los pasos siguientes, ya que el mensaje cambió
            fnv1_hash = None
            mensaje_compreso = None
            paquete_enviado = None
            firma = None

        elif opcion == '2':
            if mensaje_original is None:
                print("\nError: Primero debe ingresar un mensaje (Opción 1).")
                continue

            fnv1_hash = calcular_hash_fnv1_32(mensaje_original)
            print()
            print(f"Paso 2: Hash FNV-1 del mensaje original (32 bit):")
            print(f"  > Hash (int): {fnv1_hash}")
            print(f"  > Hash (hex): {fnv1_hash:x}")  # Muestra el hash en hexadecimal

        elif opcion == '3':
            if mensaje_original is None:
                print()
                print("Error: Primero debe ingresar un mensaje (Opción 1).")
                continue

            mensaje_compreso = comprimir_rle(mensaje_original)
            size_antes = len(mensaje_original.encode('utf-8'))
            size_despues = len(mensaje_compreso.encode('utf-8'))

            print()
            print(f"Paso 3: Mensaje comprimido con RLE:")
            print(f"Original: '{mensaje_original}' (Tamaño: {size_antes} bytes)")
            print(f"Compreso: '{mensaje_compreso}' (Tamaño: {size_despues} bytes)")

        elif opcion == '4':
            if fnv1_hash is None:
                print()
                print("Error: Primero calcule el hash (Opción 2).")
                continue

            print()
            print(f"Paso 4: Firmando el hash FNV-1 ({fnv1_hash})...")
            #llama a la función que genera claves Y firma el hash
            clave_privada, clave_publica, firma = generar_claves_y_firma(fnv1_hash)
            print("   (La clave privada se guarda localmente, no se envía)")

        elif opcion == '5':
            if mensaje_compreso is None or firma is None or clave_publica is None:
                print()
                print("Error: Faltan pasos. Debe tener:")
                print(" Opciones 3 y 4")
                continue

            #empaqueta los datos que se enviarían por la red/servidor
            paquete_enviado = {
                "msg_comprimido": mensaje_compreso,
                "firma_digital": firma,
                "clave_publica_emisor": clave_publica
            }
            print()
            print("Paso 5: Paquete enviado a la 'red/seridor'")
            #lo enviamos a la memoria y contiene mensaje, calve publica, privada no se envia

        elif opcion == '6':
            if paquete_enviado is None:
                print()
                print("Error: Primero debe simular el envío (Opción 5).")
                continue

            print()
            print("Proceso del Receptor")

            #receptor descomprime el mensaje
            msg_rec_comprimido = paquete_enviado["msg_comprimido"]
            msg_rec_descomprimido = descomprimir_rle(msg_rec_comprimido)

            if msg_rec_descomprimido is None:
                print("Error del Receptor: El mensaje comprimido está malformado.")
                continue

            print(f"1. Mensaje descomprimido: '{msg_rec_descomprimido}'")

            # receptor calcula SU PROPIO hash del mensaje que recibió
            hash_calculado_receptor = calcular_hash_fnv1_32(msg_rec_descomprimido)
            print(f"2. Hash FNV-1 calculado por receptor: {hash_calculado_receptor:x}")

            # receptor extrae la firma y la clave pública del paquete
            firma_recibida = paquete_enviado["firma_digital"]
            clave_publica_recibida = paquete_enviado["clave_publica_emisor"]

            #verifica la firma usando la clave pública
            es_valida = verificar_firma(
                clave_publica_recibida,
                firma_recibida,
                hash_calculado_receptor
            )

            # muestra el resultado de la verificación
            print("3. Verificando firma...")
            print()
            if es_valida:
                print("Mensaje autonteico y no modificado.")
            else:
                print("Mensaje alterado o firma no válida.")



        elif opcion == '7':
            print()
            print("Gracias por usar nuestro programa. ¡Adiós!")
            break

        else:
            print("Opción no válida. Intente de nuevo.")



main()