##########################################
# WHO IS... pero con esteroides!
##########################################
# Versión 0.4 - Cambio de "Full" a "Completo" y mejora en depuración - 09/11/2024

import subprocess
import sys
import whois
import ipaddress
import dns.resolver

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

modules = {
    "python-whois": "python-whois",
    "ipaddress": "ipaddress",
    "dns": "dnspython",
}

for module, package in modules.items():
    try:
        __import__(module)
        print(f"'{module}' está instalado.")
    except ImportError:
        print(f"'{module}' no está instalado. Instalando...")
        install(package)

#### Funciones ####
def es_ip_privada(direccion_ip):
    try:
        ip = ipaddress.ip_address(direccion_ip)
        return ip.is_private
    except ValueError:
        return False

def es_ip(direccion):
    try:
        ipaddress.ip_address(direccion)
        return True
    except ValueError:
        return False

def obtener_info_whois(objetivo, datos):
    try:
        resultado = whois.whois(objetivo)
        
        # Imprimir resultado para depuración
        print("Resultado WHOIS (depuración):", resultado)

        if datos == 2:
            info = {
                "Domain Name": resultado.domain_name,
                "Name Servers": resultado.name_servers,
                "Expiration Date": resultado.expiration_date,
                "Creation Date": resultado.creation_date,
            }
            return info
        elif datos == 1:
            # Emulación de un nivel de detalle "Completo" con los campos de interés
            info_completo = {
                "Domain Name": resultado.domain_name,
                "Registrar": resultado.registrar,
                "Whois Server": resultado.whois_server,
                "Referral URL": resultado.referral_url,
                "Updated Date": resultado.updated_date,
                "Creation Date": resultado.creation_date,
                "Expiration Date": resultado.expiration_date,
                "Name Servers": resultado.name_servers,
                "Status": resultado.status,
                "Emails": resultado.emails
            }
            return info_completo
    except Exception as e:
        return f"Error al obtener información WHOIS: {e}"

def mostrar_info(info):
    if isinstance(info, dict):
        for clave, valor in info.items():
            print(f"{clave}: {valor}\n")
    else:
        print(info)

def mostrar_menu():
    print("*" * 10)
    print("Opciones: \n")
    print("   1. Who Is")
    print("   2. NSLookup")
    print("   99. Salir")
    print("")
    try:
        opcion_seleccionada = int(input("Ingrese una opción: "))
    except ValueError:
        opcion_seleccionada = 0
    return opcion_seleccionada

################ PROGRAMA ###########################
print("#", "+" * 40, "#")
print("#       Sistema de análisis de IP's        #")
print("#", "+" * 40, "#")
print("")

opcion = 0
while opcion != 99:
    opcion = mostrar_menu()

    # Opciones del menú
    if opcion == 1:
        objetivo = input("Ingrese la dirección IP o dominio: ").strip()
        while True:
            try:
                detalle = int(input("Ingrese el nivel de detalle:\n1) Completo \n2) Acotado\nElija su opción deseada: "))
                if detalle in [1, 2]:
                    break
                else:
                    print("Seleccione una opción válida (1 o 2).")
            except ValueError:
                print("Entrada inválida. Por favor, ingrese un número (1 o 2).")
        
        if es_ip(objetivo):
            print(f"{objetivo} es una dirección IP.")
            if es_ip_privada(objetivo):
                print(f"La dirección {objetivo} pertenece a un segmento privado.\n")
            else:
                info = obtener_info_whois(objetivo, detalle)
                print("Información WHOIS para IP pública:\n")
                mostrar_info(info)
        else:
            print(f"{objetivo} es un dominio.")
            info = obtener_info_whois(objetivo, detalle)
            print("Información WHOIS para el dominio:\n")
            mostrar_info(info)

    elif opcion == 2:
        dominio = input("Ingrese el dominio para hacer NSLookup: ").strip()
        try:
            result = dns.resolver.resolve(dominio, 'CNAME')
            for cnameval in result:
                print('El objetivo CNAME es:', cnameval.target)
        except dns.resolver.NoAnswer:
            print("No se encontraron registros CNAME para este dominio.")
        except dns.resolver.NXDOMAIN:
            print("El dominio no existe.")
        except Exception as e:
            print(f"Error en NSLookup: {e}")

    elif opcion == 99:
        print("Muchas gracias por utilizar nuestro sistema\nAdios!")
        break

    else:
        print("Opción incorrecta, por favor intente nuevamente\n")
