import streamlit as st
from scanner.port_scanner import scan_ports
from scanner.http_headers import analyze_headers
from scanner.whois_lookup import get_whois_info
from scanner.ssl_checker import check_ssl_certificate
from utils.generate_report import generate_pdf_report
import socket
from datetime import datetime
import requests

# Page config
st.set_page_config(page_title="VulnScope", layout="wide", page_icon="🔐")

# Custom style
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
tab1, tab2, tab3, tab4 = st.tabs(["🧪 Analyse", "📄 Rapport PDF", "ℹ️ À propos", "🔎 Tests semi-actifs"])

with tab1:
    st.subheader("🔍 Scanner un site web")

    url = st.text_input("Entrez l'URL à analyser :", placeholder="https://exemple.com")

    if st.button("Lancer l'analyse"):
        if url:
            domain = url.replace("https://", "").replace("http://", "").split('/')[0]
            st.success(f"Analyse lancée pour : {url}")
            ip = socket.gethostbyname(domain)
            st.info(f"📡 Adresse IP résolue : {ip}")

            # Analyse
            port_results = scan_ports(domain)
            headers_result = analyze_headers(url)
            whois_result = get_whois_info(domain)
            ssl_result = check_ssl_certificate(domain)

            # Score sécurité simple
            if "error" not in headers_result:
                attendus = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"]
                manquants = [h for h in attendus if h not in headers_result]
                score = max(0, 100 - len(manquants) * 20)
                st.markdown(f"""
                    <div class='score-box'>
                        <h2 style='color: #8e44ad;'>🔐 Score de sécurité</h2>
                        <p style='font-size: 24px; color: white;'>{score}/100</p>
                    </div>
                """, unsafe_allow_html=True)

            # Grille de 2 x 2 pour les résultats
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("📡 Ports ouverts")
                if "error" in port_results:
                    st.error(port_results['error'])
                else:
                    sensitive_ports = {21, 22, 23, 25, 110, 143, 3306, 3389, 8080}
                    severity = "low"
                    for proto, ports in port_results.items():
                        st.markdown(f"**Protocole : {proto}**")
                        for port, state in ports.items():
                            color = "green" if state == "open" else "red"
                            st.markdown(f"<span style='color:{color}; font-weight: bold;'>Port {port} : {state}</span>", unsafe_allow_html=True)
                            if int(port) in sensitive_ports and state == "open":
                                severity = "high"
                    badge = "<span class='badge high'>Gravité : Haute - Ports sensibles ouverts</span>" if severity == "high" else "<span class='badge low'>Gravité : Faible - Aucun port critique détecté</span>"
                    st.markdown(badge, unsafe_allow_html=True)

                st.subheader("📦 Headers HTTP")
                if "error" in headers_result:
                    st.error(headers_result['error'])
                else:
                    for k, v in headers_result.items():
                        st.markdown(f"- **{k}** : {v}")
                    missing = [h for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-XSS-Protection"] if h not in headers_result]
                    if missing:
                        st.markdown(f"<span class='badge medium'>Gravité : Moyenne - Headers manquants</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<span class='badge low'>Gravité : Faible - Headers essentiels présents</span>", unsafe_allow_html=True)

            with col2:
                st.subheader("🔍 WHOIS")
                if "error" in whois_result:
                    st.error(whois_result['error'])
                else:
                    for k, v in whois_result.items():
                        st.markdown(f"**{k}** : {v}")
                    if whois_result.get("emails") and any("privacy" in str(e).lower() for e in whois_result["emails"]):
                        st.markdown(f"<span class='badge medium'>Gravité : Moyenne - Propriété anonymisée</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<span class='badge low'>Gravité : Faible - WHOIS transparent</span>", unsafe_allow_html=True)

                st.subheader("🔐 Certificat SSL")
                if "error" in ssl_result:
                    st.error(ssl_result['error'])
                else:
                    for k, v in ssl_result.items():
                        st.markdown(f"**{k}** : {v}")
                    if ssl_result.get("SSL Valide") is not True:
                        st.markdown(f"<span class='badge high'>Gravité : Haute - SSL invalide ou expiré</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"<span class='badge low'>Gravité : Faible - SSL valide</span>", unsafe_allow_html=True)

            st.session_state["scan"] = {
                "url": url,
                "ip": ip,
                "port_results": port_results,
                "headers_result": headers_result,
                "whois_result": whois_result,
                "ssl_result": ssl_result
            }
        else:
            st.warning("Veuillez entrer une URL valide.")

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

with tab3:
    st.subheader("ℹ️ À propos de VulnScope")
    st.markdown("""
    VulnScope est un outil open-source d'analyse basique de la sécurité web.
    - Analyse de ports avec `nmap`
    - Vérification des headers HTTP
    - Infos WHOIS
    - Certificat SSL
    - Rapport PDF automatique 📄

    **Développé avec Streamlit & Python.**
    """)

with tab4:
    st.subheader("🔎 Tests semi-actifs (XSS & SQLi GET)")
    test_url = st.text_input("Entrez une URL vulnérable (avec paramètre GET ex: ?id=1)")

    if st.button("🧪 Tester XSS"):
        if test_url:
            payload = "<script>alert('xss')</script>"
            full_url = f"{test_url}{'&' if '?' in test_url else '?'}xss={payload}"
            try:
                response = requests.get(full_url, timeout=5)
                if payload in response.text:
                    st.error("🚨 Vulnérabilité XSS détectée (reflet du script)")
                else:
                    st.success("✅ Aucun reflet détecté. Pas de XSS visible.")
            except Exception as e:
                st.warning(f"Erreur : {e}")

    if st.button("💣 Tester SQLi"):
        if test_url:
            payload = "1' OR '1'='1"
            sqli_url = test_url + ("&" if "?" in test_url else "?") + f"id={payload}"
            try:
                response = requests.get(sqli_url, timeout=5)
                if any(err in response.text.lower() for err in ["sql syntax", "mysql", "warning", "ora-"]):
                    st.error("🚨 Potentielle injection SQL détectée !")
                else:
                    st.success("✅ Pas de comportement SQLi détecté.")
            except Exception as e:
                st.warning(f"Erreur : {e}")
