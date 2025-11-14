# metodos.py

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import re


def calcular_hash_fnv1_32(texto):

    FNV_PRIME = 0x01000193
    FNV_OFFSET_BASIS = 0x811C9DC5

    hash_val = FNV_OFFSET_BASIS
    #iteramos sobre cada byte del texto
    for byte in texto.encode('utf-8'):
        #aplicamos fórmula FNV-1
        hash_val = (hash_val * FNV_PRIME) & 0xFFFFFFFF
        hash_val = (hash_val ^ byte) & 0xFFFFFFFF  #XOR
        #aquí nos aseguramos que el numero se mantenge en 32 bits

    return hash_val


#compresion RLE

def comprimir_rle(texto):
#USAMOS RLE
    if not texto:
        return ""

    comprimido = []
    count = 1
    #iteramos desde el segundo caracter
    for i in range(1, len(texto)):
        if texto[i] == texto[i - 1]:
            count += 1
        else:
            comprimido.append(f"{count}{texto[i - 1]}")
            count = 1  #reseteamos contador para el nuevo caracter

    #agregamos la última secuencia de caracteres
    comprimido.append(f"{count}{texto[-1]}")
    return "".join(comprimido)


def descomprimir_rle(comprimido):
    # buscamos uno o más dígitos seguidos de cualquier caracter
    patron = re.compile(r"(\d+)(.)")
    descomprimido = []

    try:
        #coincidencias del patron
        for match in patron.finditer(comprimido):
            count = int(match.group(1))  #el número
            char = match.group(2)  #el caracter
            descomprimido.append(char * count)  #añade el caracter repetido
    except Exception:
        return None
    return "".join(descomprimido)


#Firma

def generar_claves_y_firma(hash_a_firmar_int):
    #convertimos el hash (int) a bytes.
    try:
        #usamos 4 bytes
        hash_bytes = hash_a_firmar_int.to_bytes(4, byteorder='big', signed=False)
    except OverflowError:
        hash_bytes = (0).to_bytes(4, byteorder='big', signed=False)

    #claves RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,  #exponente público estándar
        key_size=2048,  #tamaño de clave (alto)
    )
    public_key = private_key.public_key()

    #firmamos el hash (ya convertido a bytes) con la clave privada
    signature = private_key.sign(
        hash_bytes,  #datos que queremos firmar
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print()
    print("Claves y Firma Generadas ")
    print(f"Firma Digital (hex): {signature.hex()[:60]}")

    return private_key, public_key, signature


def verificar_firma(clave_publica, firma_recibida, hash_calculado_int):
    #verificamos si una firma es valida para un hasg
    # convertimos el hash calculado por el receptor a bytes
    try:
        hash_calculado_bytes = hash_calculado_int.to_bytes(4, byteorder='big', signed=False)
    except OverflowError:
        hash_calculado_bytes = (0).to_bytes(4, byteorder='big', signed=False)

    try:
        clave_publica.verify(
            firma_recibida,  #firma que nos llegó
            hash_calculado_bytes,  # hash que calculamos
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Error en verificación: {e}")
        return False