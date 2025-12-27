# permissions_audit/adb_permission_extractor.py
import subprocess
import json
import os
import logging
from typing import List, Dict, Optional
import datetime

logging.basicConfig(level=logging.INFO)

ADB_PATH = "adb"
OUTPUT_DIR = "extracted_data"

DANGEROUS_PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_CONTACTS",
    "WRITE_CONTACTS", "ACCESS_FINE_LOCATION", "RECORD_AUDIO",
    "CAMERA", "READ_PHONE_STATE", "CALL_PHONE"
]

def run_adb_command(cmd: List[str]) -> Optional[str]:
    try:
        result = subprocess.run([ADB_PATH] + cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"ADB command failed: {' '.join(cmd)}\n{e}")
        return None

def list_installed_packages() -> List[str]:
    output = run_adb_command(["shell", "pm", "list", "packages"])
    return [line.split(":")[-1].strip() for line in output.splitlines()] if output else []

def extract_manifest_permissions(package: str) -> List[str]:
    output = run_adb_command(["shell", "dumpsys", "package", package])
    if not output:
        return []
    permissions = []
    for line in output.splitlines():
        if "permission" in line and any(dp in line for dp in DANGEROUS_PERMISSIONS):
            permissions.append(line.strip())
    return permissions

def get_runtime_permissions(package: str) -> List[str]:
    output = run_adb_command(["shell", "dumpsys", "package", package])
    permissions = []
    if output:
        for line in output.splitlines():
            if "granted=true" in line and any(dp in line for dp in DANGEROUS_PERMISSIONS):
                permissions.append(line.strip())
    return permissions

def pull_runtime_permissions_xml() -> Optional[str]:
    possible_paths = [
        "/data/system/users/0/runtime-permissions.xml",
        "/mnt/sdcard/runtime-permissions.xml"
    ]
    for path in possible_paths:
        local_path = os.path.join(OUTPUT_DIR, os.path.basename(path))
        result = run_adb_command(["pull", path, local_path])
        if result and os.path.exists(local_path):
            return local_path
    return None

def collect_logcat_logs() -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    log_file = os.path.join(OUTPUT_DIR, f"logcat_{timestamp()}.txt")
    with open(log_file, "w") as f:
        subprocess.run([ADB_PATH, "logcat", "-d"], stdout=f)
    return log_file

def check_device_admin_apps() -> List[str]:
    output = run_adb_command(["shell", "dpm", "list", "active-admins"])
    return output.splitlines() if output else []

def timestamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def save_json(data: Dict, filename: str):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# Entry point example
if __name__ == "__main__":
    packages = list_installed_packages()
    results = {}
    for pkg in packages:
        results[pkg] = {
            "manifest_permissions": extract_manifest_permissions(pkg),
            "runtime_permissions": get_runtime_permissions(pkg),
        }
    results["device_admin_apps"] = check_device_admin_apps()
    results["logcat"] = collect_logcat_logs()
    runtime_xml = pull_runtime_permissions_xml()
    results["runtime_permissions_xml"] = runtime_xml
    save_json(results, f"permissions_audit_{timestamp()}.json")


