import dns.resolver
import sys

dc_dict = {}
GREEN = '\033[0;32m'

def print_colored(message, color_code):
    RESET_COLOR = "\033[0m"
    print(f"{color_code}{message}{RESET_COLOR}")

def query_srv_records(service, domain):
    query_name = f"{service}.{domain}"
    try:
        answers = dns.resolver.resolve(query_name, 'SRV')
        for rdata in answers:
            try:
                ip_answers = dns.resolver.resolve(str(rdata.target), 'A')
                for ip in ip_answers:
                    print(f"Host: {rdata.target} --> {ip}")
                    dc_dict[str(rdata.target).rstrip('.')] = str(ip)
            except Exception as e:
                print(f"  Warning: Could not resolve IP for {rdata.target}: {e}")

    except Exception as e:
        print(f"An error occurred while querying {query_name}: {e}")

def main(fqdn_domain):
    print(f"Starting Active Directory Services discovery for domain: {fqdn_domain}\n")

    # Primary Domain Controller
    print_colored("[+] Finding the Primary Domain Controller", GREEN)
    query_srv_records("_ldap._tcp.pdc._msdcs", fqdn_domain)

    # All Domain Controllers
    print_colored("\n[+] Finding all Domain Controllers", GREEN)
    query_srv_records("_ldap._tcp.dc._msdcs", fqdn_domain)

    # Global Catalog
    print_colored("\n[+] Finding the Global Catalog(s)", GREEN)
    query_srv_records("_gc._tcp", fqdn_domain)

    # Kerberos Authentication Server
    print_colored("\n[+] Finding the Kerberos Authentication Server(s)", GREEN)
    query_srv_records("_kerberos._tcp", fqdn_domain)

    # Kerberos Password Change Server
    print_colored("\n[+] Finding the Kerberos Password Change Server(s)", GREEN)
    query_srv_records("_kpasswd._tcp", fqdn_domain)

    # LDAP Server
    print_colored("\n[+] Finding the LDAP Server(s)", GREEN)
    query_srv_records("_ldap._tcp", fqdn_domain)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <Fully Qualified Domain Name>")
        sys.exit(1)

    main(sys.argv[1])
    print_colored("\n\n[+] List of DCs:", GREEN)

    try:
        with open("dc_list.txt", "w") as f:
            for host, ip in dc_dict.items():
                line = f"{host}:{ip}"
                f.write(f"{line}\n")
                print(f"{line}")
        print_colored("\n[+] List of DCs saved to dc_list.txt", GREEN)
    except IOError as e:
        print(f"Error: Could not write to dc_list.txt: {e}")
