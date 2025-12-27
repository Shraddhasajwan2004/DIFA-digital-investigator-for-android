import os
import hashlib
import csv

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a given file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"ERROR: {e}"

def hash_all_files(directory, output_csv_path=None):
    """
    Recursively hash all files in a directory.
    Optionally save to a CSV report if output_csv_path is provided.
    """
    hash_records = []

    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, directory)
            file_hash = calculate_sha256(full_path)
            hash_records.append((rel_path, file_hash))

    # Save to CSV if path is provided
    if output_csv_path:
        os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
        with open(output_csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["File Path", "SHA256 Hash"])
            writer.writerows(hash_records)
        print(f"[+] Hash report saved at: {output_csv_path}")

    return hash_records
