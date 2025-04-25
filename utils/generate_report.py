from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime

def generate_pdf_report(filename, url, ip, port_results, headers, whois_data, ssl_data):
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4
    y = height - 60

    def write_line(text, bold=False, color=colors.black):
        nonlocal y
        c.setFont("Helvetica-Bold" if bold else "Helvetica", 10)
        c.setFillColor(color)
        c.drawString(50, y, text)
        y -= 14

    def section(title):
        nonlocal y
        y -= 10
        c.setFont("Helvetica-Bold", 12)
        c.setFillColor(colors.HexColor("#4B0082"))  # Violet foncé
        c.drawString(50, y, title)
        y -= 6
        c.setFillColor(colors.black)
        c.line(50, y, width - 50, y)
        y -= 20

    # 🛡️ Logo
    try:
        c.drawImage("assets/logo.jpg", 50, y - 40, width=100, preserveAspectRatio=True, mask='auto')
    except Exception as e:
        c.setFont("Helvetica", 10)
        c.setFillColor(colors.red)
        c.drawString(50, y - 10, f"❌ Erreur chargement logo : {e}")
        y -= 20

    # 🔐 Entête
    c.setFont("Helvetica-Bold", 14)
    c.drawString(160, y, "🔐 VulnScope - Rapport d'analyse de vulnérabilités")
    y -= 30

    write_line(f"URL analysée : {url}", bold=True)
    write_line(f"Adresse IP : {ip}")
    write_line(f"Date du scan : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 🔌 Scan des ports
    section("📡 Résultats du scan de ports")
    if "error" in port_results:
        write_line(f"Erreur : {port_results['error']}", color=colors.red)
    else:
        for proto, ports in port_results.items():
            write_line(f"Protocole : {proto}", bold=True)
            for port, state in ports.items():
                write_line(f" - Port {port} : {state}")
        write_line("💡 Recommandation : Fermez les ports inutilisés avec un firewall ou un WAF.", color=colors.darkgreen)

    # 📦 Headers HTTP
    section("📦 Analyse des headers HTTP")
    if "error" in headers:
        write_line(f"Erreur : {headers['error']}", color=colors.red)
    else:
        missing = []
        for k, v in headers.items():
            write_line(f"{k}: {v}")
        for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"]:
            if h not in headers:
                missing.append(h)
        if missing:
            write_line(f"⚠️ Headers manquants : {', '.join(missing)}", color=colors.orange)
            write_line("💡 Recommandation : Ajouter les headers de sécurité manquants.", color=colors.darkgreen)

    # 🔍 WHOIS
    section("🔍 Informations WHOIS")
    if "error" in whois_data:
        write_line(f"Erreur : {whois_data['error']}", color=colors.red)
    else:
        for k, v in whois_data.items():
            write_line(f"{k} : {v}")
        write_line("💡 Recommandation : Vérifiez la date d'expiration et protégez les emails publics.", color=colors.darkgreen)

    # 🔐 Certificat SSL
    section("🔐 Certificat SSL")
    if "error" in ssl_data:
        write_line(f"Erreur SSL : {ssl_data['error']}", color=colors.red)
    else:
        for k, v in ssl_data.items():
            write_line(f"{k} : {v}")
        write_line("💡 Recommandation : Assurez-vous que le certificat est valide et à jour.", color=colors.darkgreen)

    c.save()
