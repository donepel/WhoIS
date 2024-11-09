##########################################
# WHO IS... pero con esteroides!
##########################################
#version 0.3 Se agrega menu de opciones 31/10/2024
#Version 0.2 Se agrega seleccion de nivel de detalle para el whois 31/10/2024
#Version inicial 0.1 31/10/2024 

#### Modulos ####
import whois
import ipaddress
import dns
import dns.resolver

#### Funciones ####
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

    
def mostrar_menu():
    print ("*"*10)
    print("Opciones: \n")
    print ("   1. Who Is")
    print ("   2. NSLookup")
    print ("   99. Salir")
    print("")
    #verificacion que la opcion ingresada sea numerica
    try:
        opcion_seleccionada = int(input("Ingrese una opcion: "))
    except ValueError:
        opcion_seleccionada=0
    else:
        opcion_seleccionada=opcion_seleccionada
    return opcion_seleccionada


################ PROGRAMA ###########################
print ("#","+"*40,"#")
print ("#       Sistema de analisis de IP's        #")
print ("#","+"*40,"#")
print("")
opcion = 0

while (opcion != 99):
    opcion=mostrar_menu() 

    #Opciones del menu

    #Opcion 1.WHO IS
    if opcion == 1: 
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
    
    #Opcion 2. NSLookup
    elif opcion==2: 
        print("Aca hacemos looup")
        result = dns.resolver.resolve('mail.google.com', 'CNAME')
        for cnameval in result:
            print('The CNAME target address is :', cnameval.target)

    #Opcion 99. Salir
    elif opcion == 99: 
        print ("Muchas gracias por utilizar nuestro sistema\nAdios!")
        break
    
    #Opcion incorrecta
    else:
        print("Opcion incorrecta, por favor intente nuevamente\n")