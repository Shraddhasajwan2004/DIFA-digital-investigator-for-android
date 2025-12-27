# ✅ backend/analysis/ssl_certificate_inspector.py

import os
import ssl
import socket
import subprocess
import re
from datetime import datetime
from OpenSSL import crypto
from backend.utils.csv_writer import write_csv
from backend.session_logger import save_to_db
from backend.zip_exporter import zip_report

PCAP_FILE = "data/traffic.pcap"
OUTPUT_DIR = "forensics_output/ssl"
KNOWN_TRUSTED_CN = ["Google", "WhatsApp", "Meta", "YouTube", "Amazon"]

SHORT_EXPIRY_LABEL = "Short Expiry"
FORGED_CN_LABEL = "Forged CN"


def pull_pcap_from_android():
    os.makedirs("data", exist_ok=True)
    try:
        subprocess.run(["adb", "pull", "/sdcard/Download/traffic_capture.pcap", PCAP_FILE], check=True)
        return True
    except subprocess.CalledProcessError:
        return False


def extract_domains_from_pcap():
    if not os.path.exists(PCAP_FILE):
        return []
    result = subprocess.run([
        "tshark", "-r", PCAP_FILE,
        "-Y", 'ssl.handshake.extensions_server_name || http.host',
        "-T", "fields", "-e", "ssl.handshake.extensions_server_name", "-e", "http.host"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    domains = set()
    for line in result.stdout.strip().split('\n'):
        for item in line.split('\t'):
            domain = item.strip()
            if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
                domains.add(domain)

    return list(domains)


def is_self_signed(cert):
    return cert.get_issuer().CN == cert.get_subject().CN


def is_short_expiry(cert):
    not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), "%Y%m%d%H%M%SZ")
    not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), "%Y%m%d%H%M%SZ")
    return (not_after - not_before).days <= 30


def is_forged_cn(cert):
    cn = cert.get_subject().CN
    for known in KNOWN_TRUSTED_CN:
        if known.lower() in cn.lower():
            issuer = cert.get_issuer().CN
            if known.lower() not in issuer.lower():
                return True
    return False


def extract_certificate_info(domain):
    try:
        ctx = ssl.create_default_context()
        if hasattr(ssl, "TLSVersion"):
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(4)
        conn.connect((domain, 443))
        der_cert = conn.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

        info = {
            "Domain": domain,
            "Common Name": x509.get_subject().CN,
            "Issuer": x509.get_issuer().CN,
            "Serial Number": x509.get_serial_number(),
            "Public Key": x509.get_pubkey().bits(),
            "Valid From": x509.get_notBefore().decode("utf-8"),
            "Valid To": x509.get_notAfter().decode("utf-8"),
            "Self-Signed": "Yes" if is_self_signed(x509) else "No",
            SHORT_EXPIRY_LABEL: "Yes" if is_short_expiry(x509) else "No",
            FORGED_CN_LABEL: "Yes" if is_forged_cn(x509) else "No",
        }
        flags = [label for label in [SHORT_EXPIRY_LABEL, FORGED_CN_LABEL] if info[label] == "Yes"]
        info["Suspicious"] = ", ".join(flags) if flags else "No"
        return info
    except Exception as e:
        return {"Domain": domain, "Error": str(e)}

def parse_ssl_certificates():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    domains = extract_domains_from_pcap()
    if not domains:
        return None, None, []

    certs = [extract_certificate_info(d) for d in domains]

    headers = [
        "Domain", "Common Name", "Issuer", "Serial Number", "Public Key",
        "Valid From", "Valid To", "Self-Signed", SHORT_EXPIRY_LABEL,
        FORGED_CN_LABEL, "Suspicious"
    ]
    rows = [[c.get(h, "") for h in headers] for c in certs]

    csv_path = write_csv(rows, headers, os.path.join(OUTPUT_DIR, "ssl_certificates.csv"))
    zip_path = os.path.join(OUTPUT_DIR, "ssl_certificates.zip")
    zip_report(OUTPUT_DIR, zip_path)
    save_to_db(datetime.now().isoformat(), "N/A", csv_path, None, workflow="ssl")

    return csv_path, zip_path, certs

