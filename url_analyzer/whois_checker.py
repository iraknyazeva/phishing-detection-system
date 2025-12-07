import whois
import datetime


def check_whois(domain):
    result = {"created": None, "expires": None, "age_days": 0, "error": ""}
    try:
        w = whois.whois(domain)
        created = w.creation_date
        expires = w.expiration_date

        if isinstance(created, list):
            created = created[0]
        if isinstance(expires, list):
            expires = expires[0]

        result["created"] = created.strftime('%Y-%m-%d') if created else None
        result["expires"] = expires.strftime('%Y-%m-%d') if expires else None

        if created:
            age = (datetime.datetime.now() - created).days
            result["age_days"] = age
    except Exception as e:
        result["error"] = str(e)

    return result