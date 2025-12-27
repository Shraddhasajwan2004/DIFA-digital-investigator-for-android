import requests
from project_config import VT_API_KEY

def is_domain_suspicious(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            suspicious = data["data"]["attributes"]["last_analysis_stats"]["suspicious"]
            if malicious > 0:
                return "VT_Malicious"
            elif suspicious > 0:
                return "VT_Suspicious"
            else:
                return "VT_Clean"
        else:
            return "VT_Unknown"
    except Exception:
        return "VT_Error"
