import socket
import requests
import sys

def get_ip_info(hostname):
    """
    Gets all IP addresses (IPv4 & IPv6) for a hostname.
    This is "more accurate" than gethostbyname.
    """
    print(f"[*] Looking up IP addresses for: {hostname}\n")
    ips = {'ipv4': set(), 'ipv6': set()}
    try:
        # Use getaddrinfo for modern IP resolution (incl. IPv6)
        for info in socket.getaddrinfo(hostname, None):
            family, _, _, _, sockaddr = info
            ip_address = sockaddr[0]
            
            if family == socket.AF_INET:
                ips['ipv4'].add(ip_address)
            elif family == socket.AF_INET6:
                ips['ipv6'].add(ip_address)
                
    except socket.gaierror:
        print(f"[!] Error: Domain '{hostname}' could not be resolved.")
        sys.exit(1)
    
    if not ips['ipv4'] and not ips['ipv6']:
        print(f"[!] No IP addresses found for {hostname}.")
        sys.exit(1)
        
    return ips

def get_ip_details(ip_address):
    """
    NEW FEATURE: Get detailed info (Geo, ISP, ASN) from an API.
    """
    print(f"\n--- Analyzing IP: {ip_address} ---")
    
    # 1. Feature: Reverse DNS
    try:
        reverse_dns = socket.gethostbyaddr(ip_address)[0]
        print(f"  [+] Reverse DNS : {reverse_dns}")
    except (socket.herror, socket.gaierror):
        print("  [-] Reverse DNS : Not found (No PTR record).")

    # 2. Feature: Geolocation & ISP Info (More Accurate)
    # Using a different API for richer data
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,lat,lon,isp,org,as,query"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status() # Check for HTTP errors
        data = response.json()
        
        if data.get('status') == 'success':
            print("  [+] Detailed Info (ip-api.com):")
            # Format the output neatly
            print(f"    {'ISP':<12} : {data.get('isp', 'N/A')}")
            print(f"    {'Organization':<12} : {data.get('org', 'N/A')}")
            print(f"    {'ASN':<12} : {data.get('as', 'N/A')}")
            print(f"    {'Location':<12} : {data.get('city', 'N/A')}, {data.get('country', 'N/A')}")
            print(f"    {'Coordinates':<12} : (Lat: {data.get('lat', 'N/A')}, Lon: {data.get('lon', 'N/A')})")
        else:
            print(f"  [!] Failed to get detail info: {data.get('message', 'Unknown error')}")
            
    except requests.exceptions.RequestException as e:
        print(f"  [!] Error contacting API: {e}")

def scan_ports(ip_address):
    """
    NEW FEATURE: Perform a basic port scan.
    """
    print("  [+] Scanning common ports...")
    
    # List of common ports to check
    common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080]
    open_ports = []
    
    # Determine socket family based on IP format
    try:
        ip_family = socket.AF_INET6 if ':' in ip_address else socket.AF_INET
    except TypeError:
        return # Failed if IP is invalid

    for port in common_ports:
        # Create a new socket for each port
        try:
            with socket.socket(ip_family, socket.SOCK_STREAM) as s:
                s.settimeout(0.5) # Timeout so we don't wait long
                # connect_ex() returns 0 on success
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
        except socket.error:
            # Error creating socket (e.g., IPv6 not supported)
            pass 

    if open_ports:
        print(f"    [!] OPEN PORTS: {', '.join(map(str, open_ports))}")
    else:
        print("    [-] No common ports appear to be open.")

def main():
    try:
        hostname = input('Enter a domain name: ')
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(0)

    # Step 1: Get all IPs (Accuracy)
    all_ips = get_ip_info(hostname)
    
    if all_ips['ipv4']:
        print(f"[*] Found {len(all_ips['ipv4'])} IPv4 Address(es):")
        for ip in all_ips['ipv4']:
            print(f"    - {ip}")
            
    if all_ips['ipv6']:
        print(f"[*] Found {len(all_ips['ipv6'])} IPv6 Address(es):")
        for ip in all_ips['ipv6']:
            print(f"    - {ip}")

    # Step 2: Analyze each discovered IP (Scanning Features)
    all_ip_list = list(all_ips['ipv4']) + list(all_ips['ipv6'])
    
    for ip in all_ip_list:
        get_ip_details(ip) # Geolocation, ISP, Reverse DNS
        scan_ports(ip)     # Port Scanning
        print("-" * 40) # Separator

if __name__ == "__main__":
    main()
