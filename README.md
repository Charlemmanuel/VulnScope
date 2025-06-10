# 🔐 VulnScope

**VulnScope** est un outil web de détection de vulnérabilités basiques, développé avec **Python** et **Streamlit**.  
Il permet d’évaluer la sécurité d’un site web à travers des tests passifs et semi-actifs.

## 🛡️ Ce que fait VulnScope

- 📡 **Scan des ports** ouverts (via `nmap`)
- 📦 **Analyse des headers HTTP**
- 🔐 **Vérification du certificat SSL**
- 🔍 **Informations WHOIS** + support IPv6 & détection DNS Failover
- 📊 **Tableaux interactifs** avec `st.dataframe`
- 🧠 **Score de sécurité** calculé automatiquement
- 📄 **Génération de rapports PDF téléchargeables**

> ⚠️ Les tests semi-actifs (XSS & SQLi) ont été retirés car non pertinents dans ce contexte.

---

## 🚀 Lancer l’application en local

### 1. Installer les dépendances

```bash
pip install -r requirements.txt
