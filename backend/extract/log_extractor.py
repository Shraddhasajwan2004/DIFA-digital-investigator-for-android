# backend/extract/adb_hidden_apps_extractor.py

import os
import subprocess
import json
import re

DUMP_DIR = "data_dump/hidden_apps"
os.makedirs(DUMP_DIR, exist_ok=True)

def adb_shell(cmd):
    full_cmd = ["adb", "shell"] + cmd.split()
    result = subprocess.run(full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout.strip()

def list_installed_packages():
    output = adb_shell("pm list packages -3")
    return [line.replace("package:", "") for line in output.splitlines() if line.strip()]

def get_apk_path(package_name):
    output = adb_shell(f"pm path {package_name}")
    match = re.search(r'package:(.*)', output)
    return match.group(1) if match else ""

def get_permissions(package_name):
    output = adb_shell(f"dumpsys package {package_name}")
    match = re.search(r"requested permissions:\n(.*?)\ninstall permissions:", output, re.DOTALL)
    if match:
        perms = re.findall(r"android\.permission\.[A-Z_]+", match.group(1))
        return list(set(perms))
    return []

def get_intents(package_name):
    output = adb_shell(f"dumpsys package {package_name}")
    return re.findall(r"android\.intent\.category\.[A-Z_]+", output)

def get_apk_size_mb(apk_path):
    if not apk_path:
        return 0
    output = subprocess.run(["adb", "shell", f"ls -l {apk_path}"], stdout=subprocess.PIPE, text=True)
    match = re.search(r"(\d+)", output.stdout)
    if match:
        size_bytes = int(match.group(1))
        return round(size_bytes / (1024 * 1024), 2)
    return 0

def extract_hidden_apps_data():
    apps_data = []
    packages = list_installed_packages()
    for pkg in packages:
        apk_path = get_apk_path(pkg)
        permissions = get_permissions(pkg)
        intents = get_intents(pkg)
        size_mb = get_apk_size_mb(apk_path)
        app_label = adb_shell(f"dumpsys package {pkg} | grep -m 1 ApplicationInfo")
        app_name = pkg.split(".")[-1] if not app_label else app_label.strip().split()[-1]

        apps_data.append({
            "app_name": app_name,
            "package_name": pkg,
            "permissions": permissions,
            "intents": intents,
            "apk_size_mb": size_mb,
            "first_seen": adb_shell("date +%Y-%m-%d")
        })

    json_path = os.path.join(DUMP_DIR, "installed_apps.json")
    with open(json_path, "w") as f:
        json.dump(apps_data, f, indent=4)

    return apps_data, json_path


if __name__ == "__main__":
    data, path = extract_hidden_apps_data()
    print(f"[+] Extracted {len(data)} apps to {path}")
