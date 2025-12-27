import re
from backend.utils.threat_intel import is_domain_suspicious

# ----------------------------
# CONFIGURABLE WEIGHTS
# ----------------------------
weights = {
    "spf_fail": 2,
    "dkim_fail": 1.5,
    "dmarc_fail": 1.5,
    "timestamp_anomaly": 2,
    "many_at_once": 2.5,
    "suspicious_domain": 3,
    "vt_malicious": 3,
    "vt_suspicious": 2
}

# ----------------------------
# SCORING FUNCTION
# ----------------------------
def score_email(features: dict) -> dict:
    """
    Given a feature dict, calculate risk score and risk level.
    features keys: spf, dkim, dmarc, timestamp_anomaly, domain, count_same_timestamp
    """
    score = 0
    reasons = []

    # SPF, DKIM, DMARC
    if features.get("spf", "").lower() != "pass":
        score += weights["spf_fail"]
        reasons.append("SPF failed")

    if features.get("dkim", "").lower() != "pass":
        score += weights["dkim_fail"]
        reasons.append("DKIM failed")

    if features.get("dmarc", "").lower() != "pass":
        score += weights["dmarc_fail"]
        reasons.append("DMARC failed")

    # Timestamp anomaly (future date, duplicate timestamp, weekend night)
    if features.get("timestamp_anomaly"):
        score += weights["timestamp_anomaly"]
        reasons.append("Timestamp anomaly")

    # Bulk sending (e.g., > 10 at same timestamp)
    if features.get("count_same_timestamp", 0) >= 10:
        score += weights["many_at_once"]
        reasons.append("Bulk emails sent at once")

    # Suspicious domain (heuristic check)
    domain = features.get("domain", "")
    if is_suspicious_domain(domain):
        score += weights["suspicious_domain"]
        reasons.append("Domain looks suspicious")

    # VirusTotal check (optional if internet available)
    vt_status = is_domain_suspicious(domain)
    if vt_status == "VT_Malicious":
        score += weights["vt_malicious"]
        reasons.append("VirusTotal: Malicious")
    elif vt_status == "VT_Suspicious":
        score += weights["vt_suspicious"]
        reasons.append("VirusTotal: Suspicious")

    # Risk level
    if score >= 6:
        risk = "High"
    elif score >= 3:
        risk = "Intermediate"
    else:
        risk = "Low"

    return {
        "score": score,
        "risk_level": risk,
        "reasons": reasons
    }

# ----------------------------
# HEURISTIC DOMAIN CHECK
# ----------------------------
def is_suspicious_domain(domain: str) -> bool:
    suspicious_keywords = ["xyz", "click", "discount", "darkweb", "tor", "onion", "proxy"]
    free_providers = ["mail.ru", "protonmail.com", "yopmail.com", "tutanota.com"]
    tld_blacklist = [".xyz", ".top", ".buzz", ".ru", ".onion"]

    if any(domain.endswith(tld) for tld in tld_blacklist):
        return True
    if any(free in domain for free in free_providers):
        return True
    if any(kw in domain.lower() for kw in suspicious_keywords):
        return True
    return False
