import whois

def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        return {
            "Registrar": info.registrar,
            "Nom de domaine": info.domain_name,
            "Date de création": str(info.creation_date),
            "Date d'expiration": str(info.expiration_date),
            "Emails": info.emails,
            "Organisation": info.org,
            "Pays": info.country
        }
    except Exception as e:
        return {"error": str(e)}
