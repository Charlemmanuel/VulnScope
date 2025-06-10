import streamlit as st
from scanner.port_scanner import scan_ports
from scanner.http_headers import analyze_headers
from scanner.whois_lookup import get_whois_info
from scanner.ssl_checker import check_ssl_certificate
from utils.generate_report import generate_pdf_report
import socket
from datetime import datetime
import requests
import pandas as pd
import dns.resolver
import dns.exception

# Page config
st.set_page_config(page_title="VulnScope", layout="wide", page_icon="🔐")

# Style personnalisé
st.markdown("""
    <style>
    .stApp { background-color: #0e0e0e; }
    h1, h2, h3 { color: #8e44ad; font-size: 30px; }
    .score-box {
        background-color: #1a1a1a;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 20px;
    }
    .badge {
        display: inline-block;
        padding: 6px 12px;
        border-radius: 5px;
        font-size: 0.9rem;
        font-weight: bold;
        margin-top: 5px;
    }
    div[data-testid="stDataFrame"] div {
        font-size: 25px !important;
    }
    .high { background-color: #ff4d4d; color: white; }
    .medium { background-color: #ffa500; color: white; }
    .low { background-color: #28a745; color: white; }
    </style>
""", unsafe_allow_html=True)

# Header
col1, col2 = st.columns([1, 4])
with col1:
    st.image("assets/logo.jpg", width=100)
with col2:
    st.markdown("<h1 style='color:#8e44ad;'>🔐 VulnScope</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:white;'>Analyse rapide de vulnérabilités web 💻</p>", unsafe_allow_html=True)
st.markdown("<hr style='border: 1px solid #8e44ad;'>", unsafe_allow_html=True)

# Tabs
tab1, tab2, tab3 = st.tabs(["🧪 Analyse", "📄 Rapport PDF", "ℹ️ À propos"])

# ============ ANALYSE PRINCIPALE ============
with tab1:
    st.subheader("🔍 Scanner un site web")

    url = st.text_input("Entrez l'URL à analyser :", placeholder="https://exemple.com")

    if st.button("Lancer l'analyse"):
        if url:
            domain = url.replace("https://", "").replace("http://", "").split('/')[0]
            st.success(f"Analyse lancée pour : {url}")

            ip = None
            ipv6_addresses = []

            try:
                ip = socket.gethostbyname(domain)
                st.info(f"📡 Adresse IPv4 : {ip}")
            except socket.gaierror:
                st.error("❌ Erreur DNS : nom de domaine introuvable")
            except Exception as e:
                st.warning(f"Erreur lors de la résolution IPv4 : {e}")

            try:
                infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
                ipv6_addresses = list(set([x[4][0] for x in infos]))
                if ipv6_addresses:
                    st.info("🌐 Adresse(s) IPv6 : " + ", ".join(ipv6_addresses))
            except Exception as e:
                st.warning("IPv6 non disponible ou non résolu.")

            # DNS Failover check
            try:
                dns_resolver = dns.resolver.Resolver()
                dns_resolver.timeout = 2
                dns_resolver.lifetime = 2
                answers = dns_resolver.resolve(domain)
                resolved_ips = [a.address for a in answers]
                st.success(f"✅ DNS fonctionne : {', '.join(resolved_ips)}")
            except dns.exception.Timeout:
                st.warning("⚠️ DNS timeout (failover ou serveur lent)")
            except Exception as e:
                st.error(f"Erreur DNS : {e}")

            # Analyse
            port_results = scan_ports(domain)
            headers_result = analyze_headers(url)
            whois_result = get_whois_info(domain)
            ssl_result = check_ssl_certificate(domain)

            # Score simple basé sur headers HTTP
            score = 100
            details = []

            # 1. Headers HTTP (max -40)
            attendus = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"]
            if "error" not in headers_result:
                manquants = [h for h in attendus if h not in headers_result]
                score -= len(manquants) * 10
                if manquants:
                    details.append(f"- Headers manquants : {', '.join(manquants)} (-{len(manquants) * 10} pts)")
            else:
                score -= 40
                details.append("- Erreur lors de l'analyse des headers (-40 pts)")

            # 2. Ports sensibles (max -20)
            sensitive_ports = {21, 22, 23, 25, 110, 143, 3306, 3389, 8080}
            sensitive_open = False
            if "error" not in port_results:
                for proto, ports in port_results.items():
                    for port, state in ports.items():
                        if int(port) in sensitive_ports and state == "open":
                            sensitive_open = True
                            break
            if sensitive_open:
                score -= 20
                details.append("- Ports sensibles ouverts (-20 pts)")

            # 3. Certificat SSL (max -20)
            if "error" not in ssl_result:
                if ssl_result.get("SSL Valide") is not True:
                    score -= 20
                    details.append("- Certificat SSL invalide ou expiré (-20 pts)")
            else:
                score -= 20
                details.append("- Erreur lors de l'analyse SSL (-20 pts)")

            # 4. WHOIS (max -10)
            if "error" not in whois_result:
                if whois_result.get("Emails") and any("privacy" in str(e).lower() for e in whois_result["Emails"]):
                    score -= 10
                    details.append("- Informations WHOIS masquées (-10 pts)")
            else:
                score -= 10
                details.append("- Erreur WHOIS (-10 pts)")

            # 5. DNS check (max -10)
            if 'DNS fonctionne' not in locals():
                score -= 10
                details.append("- Problème de résolution DNS (-10 pts)")

            # Score final propre
            score = max(0, min(score, 100))

            st.markdown(f"""
                <div class='score-box'>
                    <h2 style='color: #8e44ad;'>🔐 Score de sécurité</h2>
                    <p style='font-size: 24px; color: white;'>{score}/100</p>
                </div>
            """, unsafe_allow_html=True)

            if details:
                st.markdown("<br>".join([f"✅ {d}" for d in details]), unsafe_allow_html=True)

            col1, col2 = st.columns(2)

            with col1:
                st.subheader("📡 Ports ouverts")
                if "error" in port_results:
                    st.error(port_results['error'])
                else:
                    flat = []
                    severity = "low"
                    sensitive_ports = {21, 22, 23, 25, 110, 143, 3306, 3389, 8080}
                    for proto, ports in port_results.items():
                        for port, state in ports.items():
                            flat.append({"Protocole": proto, "Port": port, "État": state})
                            if int(port) in sensitive_ports and state == "open":
                                severity = "high"
                    st.dataframe(pd.DataFrame(flat))
                    badge = "<span class='badge high'>Gravité : Haute - Ports sensibles ouverts</span>" if severity == "high" else "<span class='badge low'>Gravité : Faible - Aucun port critique détecté</span>"
                    st.markdown(badge, unsafe_allow_html=True)

                st.subheader("📦 Headers HTTP")
                if "error" in headers_result:
                    st.error(headers_result['error'])
                else:
                    header_df = pd.DataFrame([{"Header": k, "Valeur": str(v)} for k, v in headers_result.items()])
                    st.dataframe(header_df, use_container_width=True)
                    missing = [h for h in attendus if h not in headers_result]
                    if missing:
                        st.markdown(f"<span class='badge medium'>Gravité : Moyenne - Headers manquants</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<span class='badge low'>Gravité : Faible - Headers essentiels présents</span>", unsafe_allow_html=True)

            with col2:
                st.subheader("🔍 WHOIS")
                if "error" in whois_result:
                    st.error(whois_result['error'])
                else:
                    whois_df = pd.DataFrame([{"Champ": k, "Valeur": str(v)} for k, v in whois_result.items()])
                    st.dataframe(whois_df, use_container_width=True)
                    if whois_result.get("emails") and any("privacy" in str(e).lower() for e in whois_result["emails"]):
                        st.markdown(f"<span class='badge medium'>Gravité : Moyenne - Propriété anonymisée</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<span class='badge low'>Gravité : Faible - WHOIS transparent</span>", unsafe_allow_html=True)

                st.subheader("🔐 Certificat SSL")
                if "error" in ssl_result:
                    st.error(ssl_result['error'])
                else:
                    ssl_df = pd.DataFrame([{"Champ": k, "Valeur": str(v)} for k, v in ssl_result.items()])
                    st.dataframe(ssl_df, use_container_width=True)
                    if ssl_result.get("SSL Valide") is not True:
                        st.markdown(f"<span class='badge high'>Gravité : Haute - SSL invalide ou expiré</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<span class='badge low'>Gravité : Faible - SSL valide</span>", unsafe_allow_html=True)

            # Stockage session
            st.session_state["scan"] = {
                "url": url,
                "ip": ip,
                "port_results": port_results,
                "headers_result": headers_result,
                "whois_result": whois_result,
                "ssl_result": ssl_result
            }

# ============ RAPPORT PDF ============
with tab2:
    st.subheader("📄 Générer le rapport PDF")

    if "scan" in st.session_state:
        scan = st.session_state["scan"]
        if st.button("📥 Générer un rapport PDF", key="genpdf"):
            filename = f"rapport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            generate_pdf_report(
                filename,
                scan["url"],
                scan["ip"],
                scan["port_results"],
                scan["headers_result"],
                scan["whois_result"],
                scan["ssl_result"]
            )
            with open(filename, "rb") as f:
                st.download_button("📄 Télécharger le rapport PDF", data=f, file_name=filename, mime="application/pdf")
    else:
        st.info("Lance d'abord une analyse pour générer le rapport.")

# ============ À PROPOS ============
with tab3:
    st.subheader("ℹ️ À propos de VulnScope")
    st.markdown("""
    VulnScope est un outil open-source d'analyse basique de la sécurité web.
    - Analyse de ports avec `nmap`
    - Vérification des headers HTTP
    - Infos WHOIS
    - Certificat SSL
    - Rapport PDF automatique 📄
    - Résolution IPv6 et détection d'erreurs DNS
    - Affichage clair via tableaux dynamiques

    **Développé avec Streamlit & Python.**
    """)
