#  VulnScope

**VulnScope** est un outil d'analyse de vulnérabilités web développé avec Python & Streamlit.  
Il détecte les failles courantes comme :

- Ports ouverts (via `nmap`)
- Headers HTTP manquants
- Certificats SSL expirés
- Infos WHOIS
- Tests semi-actifs : XSS, SQLi

## 🚀 Lancer l'application

```bash
pip install -r requirements.txt
streamlit run app.py
