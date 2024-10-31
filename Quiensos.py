##########################################
# WHO IS... pero con esteroides!
##########################################
#Version 0.2 se agrega seleccion de nivel de detalle 31/10/2024
#Version inicial 0.1 31/10/2024 
import whois
import ipaddress

def es_ip_privada(direccion_ip):
    ip = ipaddress.ip_address(direccion_ip)
    return ip.is_private

def es_ip(direccion):
    try:
        ipaddress.ip_address(direccion)
        return True  # Es una IP
    except ValueError:
        return False  # Es un dominio

def obtener_info_whois(objetivo,datos):
        if datos == 2:
            print("info acotada")
            try:
                resultado = whois.whois(objetivo)
                info = {
                    "Domain Name": resultado.domain_name,
                    "Name Servers": resultado.name_servers,
                    "Expiration Date": resultado.expiration_date,
                    "Creation Date": resultado.creation_date,
                }
                return info
            except Exception as e:
                return f"Error al obtener información WHOIS: {e}"
                
        elif datos == 1:
                resultado = whois.whois(objetivo)
                return resultado

def mostrar_info(info):
    if isinstance(info, dict):
        for clave, valor in info.items():
            print(f"{clave}: {valor}\n")
    else:
        print(info)

################ PROGRAMA ###########################
# Entrada del usuario
objetivo = input("Ingrese la dirección IP o dominio: ")
detalle = int(input("Ingrede el nivel de detalle:\n1) Full \n2) Acotado\nElija su opcion deseada: "))

# Verifica si es una IP o un dominio y actúa en consecuencia
if es_ip(objetivo):
    print(f"{objetivo} es una dirección IP.")
    if es_ip_privada(objetivo):  # Es una IP privada
        print(f"La dirección {objetivo} pertenece a un segmento privado.\n")
    else:  # Es una IP pública
        info = obtener_info_whois(objetivo,detalle)
        print("Información WHOIS para IP pública:\n")
        mostrar_info(info)
else:
    print(f"{objetivo} es un dominio.")
    info = obtener_info_whois(objetivo,detalle)
    print("Información WHOIS para el dominio:\n")
    mostrar_info(info)