##########################################
# Like WHO IS... but with steroids!
##########################################
# MODULE IMPORTS
import subprocess
import sys
import whois
import ipaddress
import dns.resolver

# Colors for output formatting
MAGENTA = "\033[35m"
RESET = "\033[0m"
GREEN = "\033[32m"

# FUNCTIONS
def install(package):
    """
    Installs the given package using pip.
    """
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Required modules and their corresponding pip packages
modules = {
    "python-whois": "python-whois",
    "ipaddress": "ipaddress",
    "dns": "dnspython",
}

# Check and install missing modules
for module, package in modules.items():
    try:
        __import__(module)
        print(f"'{module}' is already installed.")
    except ImportError:
        print(f"'{module}' is not installed. Installing...")
        install(package)

def is_private_ip(ip_address):
    """
    Determines if an IP address belongs to a private range.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False

def is_ip(address):
    """
    Validates whether a string is a valid IP address.
    """
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def whois_report(target, detail_level):
    """
    Fetches WHOIS information for a domain or IP.
    
    Args:
        target (str): The domain or IP address to query.
        detail_level (int): 1 for full details, 2 for summarized details.
    
    Returns:
        dict or str: WHOIS information or an error message.
    """
    try:
        result = whois.whois(target)
        if detail_level == 2:  # Summarized details
            info = {
                "Domain Name": result.domain_name,
                "Name Servers": result.name_servers,
                "Expiration Date": result.expiration_date,
                "Creation Date": result.creation_date,
            }
            return info
        elif detail_level == 1:  # Full details
            full_info = {k: v for k, v in result.items() if v}
            return full_info
    except Exception as e:
        return f"Error fetching WHOIS information: {e}"

def nslookup_report(domain):
    """
    Performs an NSLookup on a domain and retrieves DNS records.
    
    Args:
        domain (str): The domain to query.
    
    Returns:
        dict: A dictionary containing various DNS records.
    """
    dns_info = {"CNAME": [], "A": [], "MX": [], "TXT": [], "AAAA": []}
    try:
        # Query CNAME
        try:
            result_cname = dns.resolver.resolve(domain, 'CNAME')
            dns_info["CNAME"] = [cnameval.target.to_text() for cnameval in result_cname]
        except dns.resolver.NoAnswer:
            pass
        
        # Query A
        try:
            result_a = dns.resolver.resolve(domain, 'A')
            dns_info["A"] = [a.to_text() for a in result_a]
        except dns.resolver.NoAnswer:
            pass
        
        # Query MX
        try:
            result_mx = dns.resolver.resolve(domain, 'MX')
            dns_info["MX"] = [(mx.exchange.to_text(), mx.preference) for mx in result_mx]
        except dns.resolver.NoAnswer:
            pass
        
        # Query TXT
        try:
            result_txt = dns.resolver.resolve(domain, 'TXT')
            dns_info["TXT"] = [txt.to_text() for txt in result_txt]
        except dns.resolver.NoAnswer:
            pass

        # Query AAAA
        try:
            result_aaaa = dns.resolver.resolve(domain, 'AAAA')
            dns_info["AAAA"] = [aaaa.to_text() for aaaa in result_aaaa]
        except dns.resolver.NoAnswer:
            pass

    except dns.resolver.NXDOMAIN:
        return {"Error": "The domain does not exist."}
    except Exception as e:
        return {"Error": str(e)}
    
    return dns_info

def display_info(info):
    """
    Displays information in a formatted way.
    
    Args:
        info (dict or str): The information to display.
    """
    if isinstance(info, dict):
        for key, value in info.items():
            if isinstance(value, list):
                value = ", ".join(map(str, value))
            print(f"{MAGENTA}{key}: {value}{RESET}")
    else:
        print(info)

def display_menu():
    """
    Displays the main menu and returns the user's selection.
    """
    print(f"{GREEN}Options:{RESET}")
    print(f"{GREEN}   1. WHOIS Query{RESET}")
    print(f"{GREEN}   2. NSLookup{RESET}")
    print(f"{GREEN}   9. FULL Report (WHOIS + NSLookup){RESET}")
    print(f"{GREEN}   99. Exit{RESET}")
    print("")
    try:
        selected_option = int(input("Please select an option: "))
    except ValueError:
        selected_option = 0
    return selected_option

# PROGRAM
print(f"{GREEN}#", "+" * 40, "#")
print("#       IP Analysis System                #")
print("#          by Don_Epel                   #")
print("#", "+" * 40, "#")
print("Version 0.2 18/11/2024")
print(f"{RESET}")

option = 0
while option != 99:
    # Show the main menu
    option = display_menu()

    if option == 1:  # WHOIS Query
        target = input("Enter the IP address or domain: ").strip()
        detail_level = int(input("Select detail level:\n1) Full \n2) Summary\nEnter your choice: "))
        info = whois_report(target, detail_level)
        print(f"{GREEN}WHOIS Report:{RESET}")
        display_info(info)

    elif option == 2:  # NSLookup
        domain = input("Enter the domain for NSLookup: ").strip()
        dns_info = nslookup_report(domain)
        print(f"{GREEN}NSLookup Report:{RESET}")
        display_info(dns_info)

    elif option == 9:  # FULL Report
        target = input("Enter the IP address or domain: ").strip()
        detail_level = 1  # Always full detail for WHOIS in FULL Report
        print(f"{GREEN}\nWHOIS Report:{RESET}")
        info = whois_report(target, detail_level)
        display_info(info)
        
        if not is_ip(target):  # NSLookup only applies to domains
            print(f"{GREEN}\nNSLookup Report:{RESET}")
            dns_info = nslookup_report(target)
            display_info(dns_info)

    elif option == 99:  # Exit
        print("Thanks for using my program. Take care!")
        break

    else:
        print("Invalid option. Please try again.\n")
