import os
import subprocess
from datetime import datetime
from backend.utils.file_hash import hash_all_files
SDCARD_PCAP_PATH = "/sdcard/capture.pcap"
def is_adb_device_connected():
    """Check if an Android device is connected via ADB."""
    try:
        result = subprocess.check_output(['adb', 'devices'], encoding='utf-8')
        lines = result.strip().split('\n')
        connected_devices = [line for line in lines if '\tdevice' in line]
        if connected_devices:
            device_id = connected_devices[0].split('\t')[0]
            return True, device_id
        return False, None
    except subprocess.CalledProcessError:
        return False, None


def create_output_directory(base_dir='data_dump'):
    """Create timestamped output directory for pulled data."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = os.path.join(base_dir, f"android_image_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def pull_accessible_filesystem(output_dir):
    """
    Pull accessible directories from Android device.
    NOTE: Only pulls user-accessible directories (non-root).
    """
    pull_targets = [
        "/sdcard/DCIM",
        "/sdcard/Download",
        "/sdcard/Documents",
        "/sdcard/Android",
        "/sdcard/Music",
        "/sdcard/Movies",
        "/sdcard/Pictures",
        "/sdcard/",
        "/storage/emulated/0/",
    ]

    for target in pull_targets:
        try:
            target_name = target.strip('/').replace('/', '_')
            local_path = os.path.join(output_dir, target_name)
            os.makedirs(local_path, exist_ok=True)
            print(f"[*] Pulling {target} ...")
            subprocess.run(['adb', 'pull', target, local_path], check=True)
        except Exception as e:
            print(f"[!] Failed to pull {target}: {e}")


def auto_extract_android_filesystem(base_dir='data_dump'):
    """
    Main function to detect device and pull accessible files.
    """
    connected, device_id = is_adb_device_connected()
    if not connected:
        print("!! No ADB device connected!!")
        return None
    

    print(f"[+] Device detected: {device_id}")
    output_dir = create_output_directory(base_dir)
    print(f"[+] Output directory: {output_dir}")

    pull_accessible_filesystem(output_dir)
    print("[+] Filesystem pull complete.")
    # Generate hash report
    hash_report_path = os.path.join(output_dir, "hash_report.csv")
    hash_all_files(output_dir, hash_report_path)
    print(f"[+] Hash report saved to: {hash_report_path}")

    return {
        "device_id": device_id,
        "output_dir": output_dir,
        "hash_report": hash_report_path
    }
def pull_eml_files_from_device(local_dir="local_pull_dir"):
    os.makedirs(local_dir, exist_ok=True)
    try:
        print("[+] Pulling .eml files from /sdcard/Download/")
        subprocess.run(["adb", "pull", "/sdcard/Download/", local_dir], check=True)
    except Exception as e:
        print(f"[!] Failed to pull .eml files: {e}")


def get_adb_device_name():
    connected, device_id = is_adb_device_connected()
    return device_id if connected else "Unknown_Device"
def auto_extract_eml_files(base_dir='data_dump'):
    """ Main function to detect device and pull .eml files.
    """
    connected, device_id = is_adb_device_connected()
    if not connected:
        print("[!] No ADB device connected.")
        return None

    print(f"[+] Device detected: {device_id}")
    pull_eml_files_from_device(local_dir=base_dir)
    print("[+] .eml files pull complete.")
def pull_dns_logs_from_device():
    import subprocess
    output_dir = "data/dump"
    os.makedirs(output_dir, exist_ok=True)
    filename = f"dns_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    dest = os.path.join(output_dir, filename)
    
    try:
        subprocess.run(["adb", "pull", "/sdcard/dns_log.txt", dest], check=True)
        return dest
    except Exception as e:
        print(f"[ADB Pull] Error: {e}")
        return None
def auto_extract_android_filesystem_with_device_id(base_dir='data_dump', device_id=None):
    """
    Main function to pull accessible files from a specific device ID.
    If no device ID is provided, it will use the first connected device.
    """
    if not device_id:
        connected, device_id = is_adb_device_connected()
        if not connected:
            print("[!] No ADB device connected.")
            return None

    print(f"[+] Device detected: {device_id}")
    output_dir = create_output_directory(base_dir)
    print(f"[+] Output directory: {output_dir}")

    pull_accessible_filesystem(output_dir)
    print("[+] Filesystem pull complete.")
    
    # Generate hash report
    hash_report_path = os.path.join(output_dir, "hash_report.csv")
    hash_all_files(output_dir, output_csv_path=hash_report_path)
    print(f"[+] Hash report saved to: {hash_report_path}")
    
def pull_pcap_from_device(output_dir="data_dump/bandwidth"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    local_pcap_path = os.path.join(output_dir, f"traffic_capture_{timestamp}.pcap")

    try:
        subprocess.run(["adb", "shell", "tcpdump", "-w", SDCARD_PCAP_PATH, "-G", "10", "-W", "1"], timeout=12)
        subprocess.run(["adb", "pull", SDCARD_PCAP_PATH, local_pcap_path], check=True)
        subprocess.run(["adb", "shell", "rm", SDCARD_PCAP_PATH], check=False)
        return local_pcap_path
    except Exception as e:
        print(f"[!] ADB Pull Error: {e}")
        return None
def pull_pcap_from_device_with_id(device_id, output_dir="data_dump/bandwidth"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    local_pcap_path = os.path.join(output_dir, f"traffic_capture_{timestamp}.pcap")

    try:
        subprocess.run(["adb", "-s", device_id, "shell", "tcpdump", "-w", SDCARD_PCAP_PATH, "-G", "10", "-W", "1"], timeout=12)
        subprocess.run(["adb", "-s", device_id, "pull", SDCARD_PCAP_PATH, local_pcap_path], check=True)
        subprocess.run(["adb", "-s", device_id, "shell", "rm", SDCARD_PCAP_PATH], check=False)
        return local_pcap_path
    except Exception as e:
        print(f"[!] ADB Pull Error: {e}")
        return None