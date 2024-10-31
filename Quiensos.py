##########################################
# WHO IS... pero con esteroides!
##########################################
# 31/10/2024
# Versión inicial 0.1
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

# Entrada del usuario
objetivo = input("Ingrese la dirección IP o dominio: ")

# Verifica si es una IP o un dominio y actúa en consecuencia
if es_ip(objetivo):
    print(f"{objetivo} es una dirección IP.")
    if es_ip_privada(objetivo):  # Es una IP privada
        print(f"La dirección {objetivo} pertenece a un segmento privado.\n")
    else:  # Es una IP pública
        resultado = whois.whois(objetivo)
        print("Resultado WHOIS para IP pública:\n", resultado)
else:
    print(f"{objetivo} es un dominio.")
    resultado = whois.whois(objetivo)
    print("Resultado WHOIS para el dominio:\n", resultado)


    
