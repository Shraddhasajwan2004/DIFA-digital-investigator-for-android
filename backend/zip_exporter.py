import os
import zipfile
import hashlib

def zip_report(folder_path: str, output_zip_path: str) -> None:
    """
    Compresses the contents of folder_path into a ZIP file at output_zip_path.
    Maintains folder structure and uses deflate compression.
    """
    with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, start=folder_path)
                zipf.write(full_path, arcname)

def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Computes hash (SHA256/MD5/etc.) of a file. Default is SHA256.
    """
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def zip_and_hash(folder_path: str, output_zip_path: str, hash_algorithm: str = "sha256") -> tuple[str, str]:
    """
    Zips the folder and returns a tuple of (zip_path, hash_value).
    """
    zip_report(folder_path, output_zip_path)
    hash_val = compute_file_hash(output_zip_path, algorithm=hash_algorithm)
    return output_zip_path, hash_val
