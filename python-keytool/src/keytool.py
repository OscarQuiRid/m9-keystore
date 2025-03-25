import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID
from cryptography import x509
from datetime import datetime, timedelta

def crear_par_claves(archivo_clave_publica, archivo_keystore, contrasena):
    # Genera un par de claves RSA (privada y pública)
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,  # Tamaño de la clave RSA (4096 bits)
    )
    clave_publica = clave_privada.public_key()

    # Guarda la clave privada en un archivo, cifrada con la contraseña proporcionada
    with open(archivo_keystore, "wb") as f:
        f.write(clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(contrasena.encode())
        ))

    # Guarda la clave pública en un archivo
    with open(archivo_clave_publica, "wb") as f:
        f.write(clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Par de claves creado y almacenado en {archivo_keystore} y {archivo_clave_publica}")

def crear_csr(identificador, archivo_keystore, archivo_csr, contrasena):
    # Carga la clave privada desde el archivo, utilizando la contraseña proporcionada
    with open(archivo_keystore, "rb") as f:
        clave_privada = serialization.load_pem_private_key(
            f.read(),
            password=contrasena.encode(),
        )

    # Crea una Solicitud de Firma de Certificado (CSR) con la información proporcionada
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),  # País (2 caracteres)
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Catalonia"),  # Estado o provincia
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Montmeló"),  # Localidad
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyCompany"),  # Organización
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyCompany.cat"),  # Nombre común
    ])).sign(clave_privada, hashes.SHA256())

    # Guarda el CSR en un archivo
    with open(archivo_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"CSR creado y almacenado en {archivo_csr}")

def main():
    # Define los directorios para almacenar las claves y certificados
    dir_claves = os.path.join(os.path.dirname(__file__), 'Keys')
    dir_clave_publica = os.path.join(os.path.dirname(__file__), 'PublicKey')
    dir_certificados = os.path.join(os.path.dirname(__file__), 'Certificate')

    # Crea los directorios si no existen
    if not os.path.exists(dir_claves):
        os.makedirs(dir_claves)
    if not os.path.exists(dir_clave_publica):
        os.makedirs(dir_clave_publica)
    if not os.path.exists(dir_certificados):
        os.makedirs(dir_certificados)

    # Solicita al usuario su nombre, apellido y una contraseña para proteger la clave privada
    print("Introduce tu nombre:")
    nombre = input().strip()
    print("Introduce tu apellido:")
    apellido = input().strip()
    print("Introduce una contraseña para proteger tu clave privada:")
    contrasena = input().strip()

    # Genera un identificador a partir de las tres primeras letras del nombre y apellido
    identificador = (nombre[:3] + apellido[:3]).lower()

    # Define las rutas de los archivos para almacenar la clave privada, CSR y clave pública
    archivo_keystore = os.path.join(dir_claves, f"{identificador}_keystore.pem")
    archivo_csr = os.path.join(dir_certificados, f"{identificador}_csr.pem")
    archivo_clave_publica = os.path.join(dir_clave_publica, f"{identificador}_public.pem")

    # Crea el par de claves y el CSR
    crear_par_claves(archivo_clave_publica, archivo_keystore, contrasena)
    crear_csr(identificador, archivo_keystore, archivo_csr, contrasena)

if __name__ == "__main__":
    main()