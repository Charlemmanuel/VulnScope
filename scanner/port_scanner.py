import nmap
import socket

def scan_ports(host):
    try:
        # Résolution du nom de domaine en adresse IP
        ip = socket.gethostbyname(host)

        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments='-T4 -F')

        if ip not in scanner.all_hosts():
            return {"error": "Scan échoué — l'hôte ne répond pas ou est bloqué."}

        result = {}
        for proto in scanner[ip].all_protocols():
            ports = scanner[ip][proto].keys()
            result[proto] = {
                port: scanner[ip][proto][port]['state'] for port in ports
            }
        return result
    except Exception as e:
        return {"error": str(e)}
