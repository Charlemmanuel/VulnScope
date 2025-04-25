# scanner/port_scanner.py
import socket

def scan_ports(domain, ports=[80, 443, 21, 22, 25, 110, 143, 3306, 8080]):
    results = {"tcp": {}}
    try:
        ip = socket.gethostbyname(domain)
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                results["tcp"][port] = "open" if result == 0 else "filtered"
        return results
    except Exception as e:
        return {"error": str(e)}
