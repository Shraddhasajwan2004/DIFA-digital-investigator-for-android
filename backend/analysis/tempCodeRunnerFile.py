import os
import re
import email
import mailbox
import extract_msg
from datetime import datetime
from email.utils import parseaddr
from backend.utils.csv_writer import write_csv_with_hash
from backend.utils.file_hash import zip_report
from backend.session_logger import log_session
from backend.extract.adb_connector import get_adb_device_name, pull_eml_files_from_device
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime, parseaddr, getaddresses

# Constants
LOCAL_PULL_DIR = "local_pull_dir"
OUTPUT_DIR = "reports/email_headers"
SUSPICIOUS_DOMAINS = [".onion", ".xyz", ".tk", "mailinator.com", "tempmail", "yopmail"]
SUPPORTED_MAIL_EXTS = (".eml", ".mbox", ".msg", ".pst", ".ost", ".olm")

def extract_ip_from_received(received_headers):
    for header in received_headers[::-1]:  # Look earliest to latest
        ip_match = re.search(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?', header)
        if ip_match:
            return ip_match.group(1)
    return "Unknown"

def parse_eml_file(eml_file):
    if isinstance(eml_file, str):  # from folder path
        with open(eml_file, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
    else:  # Streamlit upload
        msg = BytesParser(policy=policy.default).parse(eml_file)
    
    
    headers = msg.items()
    header_dict = dict(headers)
    return header_dict
    # --- Sender and Receiver ---
    sender_name, sender_email = parseaddr(headers.get("From", ""))
    receiver_name, receiver_email = parseaddr(headers.get("To", ""))

    # --- Date and Time ---
    try:
        date_obj = parsedate_to_datetime(headers.get("Date", ""))
        date_str = date_obj.date().isoformat()
        time_str = date_obj.time().isoformat()
    except Exception:
        date_str = "Unknown"
        time_str = "Unknown"
def extract_email_features(header_dict):
    features = {
        "spf": "N/A",
        "dkim": "N/A",
        "dmarc": "N/A",
        "timestamp_anomaly": False,
        "count_same_timestamp": 0,
        "domain": "unknown"
    }

    # Example logic for feature extraction
    spf = "fail" if "spf=fail" in header_dict.get("Received-SPF", "").lower() else "pass"
    dkim = "fail" if "dkim=fail" in header_dict.get("Authentication-Results", "").lower() else "pass"
    dmarc = "fail" if "dmarc=fail" in header_dict.get("Authentication-Results", "").lower() else "pass"

    # Timestamp anomaly placeholder (extend as needed)
    date_str = header_dict.get("Date", "")
    timestamp_anomaly = False
    count_same_timestamp = 0  # Optional to calculate in batch

    # Domain extraction
    from_header = header_dict.get("From", "")
    domain_match = re.search(r'@([A-Za-z0-9.-]+)', from_header)
    domain = domain_match.group(1) if domain_match else "unknown"

    features.update({
        "date": date_str,
        "time": time_str,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "receiver_name": receiver_name,
        "receiver_email": receiver_email,
        "ip_address": ip_address,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "timestamp_anomaly": False,
        "count_same_timestamp": 0,
        "domain": domain
    })

    return features

def extract_spf_dkim_dmarc(header_text):
    spf = dkim = dmarc = "N/A"
    if header_text:
        spf_match = re.search(r"spf=(\w+)", header_text, re.IGNORECASE)
        dkim_match = re.search(r"dkim=(\w+)", header_text, re.IGNORECASE)
        dmarc_match = re.search(r"dmarc=(\w+)", header_text, re.IGNORECASE)
        if spf_match:
            spf = spf_match.group(1)
        if dkim_match:
            dkim = dkim_match.group(1)
        if dmarc_match:
            dmarc = dmarc_match.group(1)
    return spf, dkim, dmarc


def is_suspicious_domain(domain):
    return any(susp in domain.lower() for susp in SUSPICIOUS_DOMAINS)


def find_mail_files(root_dir):
    mail_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for file in filenames:
            if file.lower().endswith(SUPPORTED_MAIL_EXTS):
                mail_files.append(os.path.join(dirpath, file))
    return mail_files


def parse_email_headers_session():
    mail_files = find_mail_files(LOCAL_PULL_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    results, previews = [], []
    failed_spf, failed_dkim, failed_dmarc = [], [], []

    headers = ["Email File", "SPF", "DKIM", "DMARC", "Suspicious"]

    for file_path in mail_files:
        filename = os.path.basename(file_path)
        ext = filename.lower().split('.')[-1]

        try:
            if ext == "eml":
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    msg = email.message_from_file(f)
                    header = msg.as_string()
                    subject = msg.get("Subject", "")
                    from_email = parseaddr(msg.get("From"))[1]
                    to = msg.get("To", "")
                    date = msg.get("Date", "")
                    body = extract_body_from_msg(msg)
                    spf, dkim, dmarc = extract_spf_dkim_dmarc(header)
                    suspicious = "Yes" if any(x.lower() != "pass" and x != "N/A" for x in [spf, dkim, dmarc]) else "No"

                    previews.append({
                        "filename": filename,
                        "Subject": subject, "From": from_email,
                        "To": to, "Date": date, "Body": body, "Header": header
                    })
                    results.append([filename, spf, dkim, dmarc, suspicious])

                    if spf.lower() != "pass": failed_spf.append(results[-1])
                    if dkim.lower() != "pass": failed_dkim.append(results[-1])
                    if dmarc.lower() != "pass": failed_dmarc.append(results[-1])

            elif ext == "mbox":
                mbox = mailbox.mbox(file_path)
                for i, msg in enumerate(mbox):
                    process_email_msg(msg, f"{filename}#{i}", results, previews, failed_spf, failed_dkim, failed_dmarc)

            elif ext == "msg":
                msg = extract_msg.Message(file_path)
                header = f"From: {msg.sender}\nTo: {msg.to}\nDate: {msg.date}\nSubject: {msg.subject}"
                spf, dkim, dmarc = extract_spf_dkim_dmarc(header)
                suspicious = "Yes" if any(x.lower() != "pass" and x != "N/A" for x in [spf, dkim, dmarc]) else "No"
                previews.append({
                    "filename": filename,
                    "Subject": msg.subject, "From": msg.sender,
                    "To": msg.to, "Date": msg.date, "Body": msg.body, "Header": header
                })
                results.append([filename, spf, dkim, dmarc, suspicious])

                if spf.lower() != "pass": failed_spf.append(results[-1])
                if dkim.lower() != "pass": failed_dkim.append(results[-1])
                if dmarc.lower() != "pass": failed_dmarc.append(results[-1])

        except Exception as e:
            previews.append({
                "filename": filename,
                "Subject": f"(Error: {e})", "From": "", "To": "", "Date": "", "Body": "", "Header": ""
            })
            results.append([filename, "N/A", "N/A", "N/A", "Error"])

    csv_path = os.path.join(OUTPUT_DIR, "email_analysis.csv")
    hash_path = os.path.join(OUTPUT_DIR, "email_analysis.sha256")
    zip_path = os.path.join("reports/zipped_reports", "email_report.zip")

    write_csv_with_hash(results, headers, csv_path)
    zip_report(OUTPUT_DIR, zip_path)

    device = get_adb_device_name()
    log_session(device_name=device, csv_path=csv_path, hash_path=hash_path, workflow="email")

    preview_dict = {entry["filename"]: entry for entry in previews}

    return {
        "csv_path": csv_path,
        "hash_path": hash_path,
        "zip_path": zip_path,
        "device": device,
        "failed_spf": failed_spf,
        "failed_dkim": failed_dkim,
        "failed_dmarc": failed_dmarc,
        "headers": headers,
        "preview_data": preview_dict
    }


def extract_body_from_msg(msg_obj):
    body = ""
    if msg_obj.is_multipart():
        for part in msg_obj.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(errors='ignore')
    else:
        payload = msg_obj.get_payload(decode=True)
        if payload:
            body = payload.decode(errors='ignore') if isinstance(payload, bytes) else payload
    return body


def process_email_msg(msg, identifier, results, previews, failed_spf, failed_dkim, failed_dmarc):
    header = msg.as_string()
    subject = msg.get("Subject", "")
    from_email = parseaddr(msg.get("From"))[1]
    to = msg.get("To", "")
    date = msg.get("Date", "")
    body = extract_body_from_msg(msg)
    spf, dkim, dmarc = extract_spf_dkim_dmarc(header)
    suspicious = "Yes" if any(x.lower() != "pass" and x != "N/A" for x in [spf, dkim, dmarc]) else "No"

    previews.append({
        "filename": identifier,
        "Subject": subject, "From": from_email,
        "To": to, "Date": date, "Body": body, "Header": header
    })
    results.append([identifier, spf, dkim, dmarc, suspicious])

    if spf.lower() != "pass": failed_spf.append(results[-1])
    if dkim.lower() != "pass": failed_dkim.append(results[-1])
    if dmarc.lower() != "pass": failed_dmarc.append(results[-1])
