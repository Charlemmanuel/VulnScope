import ssl
import socket
from datetime import datetime

def check_ssl_certificate(hostname):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                valid_to = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return {
                    "Sujet": cert.get('subject', []),
                    "Émetteur": cert.get('issuer', []),
                    "Valide depuis": valid_from.strftime("%Y-%m-%d"),
                    "Expire le": valid_to.strftime("%Y-%m-%d"),
                    "SSL Valide": datetime.utcnow() < valid_to
                }
    except Exception as e:
        return {"error": str(e)}
