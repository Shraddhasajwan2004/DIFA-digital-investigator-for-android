import os
import re
import email
import mailbox
from turtle import st
import extract_msg
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
from email import policy
from email.parser import BytesParser
from streamlit.runtime.scriptrunner import get_script_run_ctx
# Use relative imports if running from Streamlit or set PYTHONPATH
from backend.utils.csv_writer import write_csv
from backend.zip_exporter  import zip_report
from backend.session_logger import log_session
from backend.extract.adb_connector import get_adb_device_name
from backend.zip_exporter import zip_and_hash




# Constants
LOCAL_PULL_DIR = "local_pull_dir"
OUTPUT_DIR = "reports/email_headers"
SUSPICIOUS_DOMAINS = [".onion", ".xyz", ".tk", "mailinator.com", "tempmail", "yopmail"]
SUPPORTED_MAIL_EXTS = (".eml", ".mbox", ".msg")

def extract_ip_from_received(received_headers):
    for header in received_headers[::-1]:
        ip_match = re.search(r'\[?(\d{1,3}(?:\.\d{1,3}){3})\]?', header)
        if ip_match:
            return ip_match.group(1)
    return "Unknown"

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

def find_mail_files(root_dir):
    mail_files = []
    for dirpath, _, filenames in os.walk(root_dir):
        for file in filenames:
            if file.lower().endswith(SUPPORTED_MAIL_EXTS):
                mail_files.append(os.path.join(dirpath, file))
    return mail_files

report_folder = "reports/email_headers/session_001"
zip_output = "reports/zipped_reports/email_session_001.zip"

zip_path, zip_hash = zip_and_hash(report_folder, zip_output)
print(f"ZIP File: {zip_path}")
print(f"SHA256: {zip_hash}")
def parse_email_headers_session():
    mail_files = find_mail_files(LOCAL_PULL_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    results = []
    previews = []
    failed_spf, failed_dkim, failed_dmarc = [], [], []

    headers = ["Email File", "Date", "Time", "Sender Name", "Sender Email", "Receiver Name", "Receiver Email", "IP", "SPF", "DKIM", "DMARC", "Suspicious"]

    for file_path in mail_files:
        filename = os.path.basename(file_path)
        ext = filename.lower().split('.')[-1]

        try:
            if ext == "eml":
                with open(file_path, 'rb') as f:
                    msg = BytesParser(policy=policy.default).parse(f)

                sender_name, sender_email = parseaddr(msg.get("From", ""))
                receiver_name, receiver_email = parseaddr(msg.get("To", ""))
                date_raw = msg.get("Date", "")
                try:
                    dt = parsedate_to_datetime(date_raw)
                    date = dt.date().isoformat()
                    time = dt.time().isoformat()
                except Exception as e:
                    date = "Unknown"
                    time = "Unknown"

                received_headers = msg.get_all("Received", [])
                ip_address = extract_ip_from_received(received_headers)

                header_raw = msg.as_string()
                spf, dkim, dmarc = extract_spf_dkim_dmarc(header_raw)
                suspicious = "Yes" if any(x.lower() != "pass" and x != "N/A" for x in [spf, dkim, dmarc]) else "No"

                results.append([
                    filename, date, time, sender_name, sender_email,
                    receiver_name, receiver_email, ip_address,
                    spf, dkim, dmarc, suspicious
                ])

                previews.append({
                    "filename": filename,
                    "From": sender_email, "To": receiver_email,
                    "Date": date, "Body": extract_body_from_msg(msg)
                })

                if spf.lower() != "pass": failed_spf.append(results[-1])
                if dkim.lower() != "pass": failed_dkim.append(results[-1])
                if dmarc.lower() != "pass": failed_dmarc.append(results[-1])

            elif ext == "mbox":
                mbox = mailbox.mbox(file_path)
                for i, msg in enumerate(mbox):
                    identifier = f"{filename}#{i}"
                    process_email_msg(msg, identifier, results, previews, failed_spf, failed_dkim, failed_dmarc)

            elif ext == "msg":
                msg = extract_msg.Message(file_path)
                spf, dkim, dmarc = extract_spf_dkim_dmarc(msg.header)
                suspicious = "Yes" if any(x.lower() != "pass" for x in [spf, dkim, dmarc]) else "No"
                results.append([
                    filename, msg.date, "", "", msg.sender, "", msg.to,
                    "Unknown", spf, dkim, dmarc, suspicious
                ])

        except Exception as e:
            results.append([filename] + ["Error"] * 11)

    # Save Results
    csv_path = os.path.join(OUTPUT_DIR, "email_analysis.csv")
    hash_path = os.path.join(OUTPUT_DIR, "email_analysis.sha256")
    zip_path = os.path.join("reports/zipped_reports", "email_report.zip")

    write_csv(results, headers, csv_path)
    zip_report(OUTPUT_DIR, zip_path)

    device = get_adb_device_name()
    log_session(case_number=st.session_state.get("case_number", "UnknownCase"), investigator_id=st.session_state.get("investigator_id", "UnknownInvestigator"), device=device, csv_path=csv_path, hash_path=hash_path, final_score=0)

    return {
        "csv_path": csv_path,
        "hash_path": hash_path,
        "zip_path": zip_path,
        "device": device,
        "failed_spf": failed_spf,
        "failed_dkim": failed_dkim,
        "failed_dmarc": failed_dmarc,
        "headers": headers,
        "preview_data": {entry["filename"]: entry for entry in previews}
    }

# Add this inside backend/analysis/email_header_analyzer.py
def parse_uploaded_eml(uploaded_file):
    from email import policy
    from email.parser import BytesParser
    from email.utils import parseaddr, parsedate_to_datetime

    msg = BytesParser(policy=policy.default).parse(uploaded_file)
    
    sender_name, sender_email = parseaddr(msg.get("From", ""))
    receiver_name, receiver_email = parseaddr(msg.get("To", ""))
    date_raw = msg.get("Date", "")
    try:
        dt = parsedate_to_datetime(date_raw)
        date = dt.date().isoformat()
        time = dt.time().isoformat()
    except Exception:
        date = "Unknown"
        time = "Unknown"

    header_raw = msg.as_string()
    spf, dkim, dmarc = extract_spf_dkim_dmarc(header_raw)
    ip_address = extract_ip_from_received(msg.get_all("Received", []))
    suspicious = "Yes" if any(x.lower() != "pass" and x != "N/A" for x in [spf, dkim, dmarc]) else "No"

    return {
        "filename": uploaded_file.name,
        "date": date,
        "time": time,
        "from": sender_email,
        "to": receiver_email,
        "ip": ip_address,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "suspicious": suspicious,
        "body": extract_body_from_msg(msg)
    }


def process_email_msg(msg, identifier, results, previews, failed_spf, failed_dkim, failed_dmarc):
    header = msg.as_string()
    spf, dkim, dmarc = extract_spf_dkim_dmarc(header)
    suspicious = "Yes" if any(x.lower() != "pass" and x != "N/A" for x in [spf, dkim, dmarc]) else "No"

    sender_name, sender_email = parseaddr(msg.get("From", ""))
    receiver_name, receiver_email = parseaddr(msg.get("To", ""))
    date_raw = msg.get("Date", "")
    try:
        dt = parsedate_to_datetime(date_raw)
        date = dt.date().isoformat()
        time = dt.time().isoformat()
    except Exception as e:
        date = "Unknown"
        time = "Unknown"

    previews.append({
        "filename": identifier,
        "From": sender_email, "To": receiver_email,
        "Date": date, "Body": extract_body_from_msg(msg)
    })

    results.append([
        identifier, date, time, sender_name, sender_email,
        receiver_name, receiver_email, "Unknown", spf, dkim, dmarc, suspicious
    ])

    if spf.lower() != "pass": failed_spf.append(results[-1])
    if dkim.lower() != "pass": failed_dkim.append(results[-1])
    if dmarc.lower() != "pass": failed_dmarc.append(results[-1])

