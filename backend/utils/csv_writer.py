import os
import csv

def write_csv(data, headers, output_path):
    """Write rows with headers to a CSV file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if headers:
            writer.writerow(headers)
        writer.writerows(data)
    return output_path

def write_df_to_csv(df, output_path):
    """Helper to write a pandas DataFrame directly to CSV using write_csv()."""
    data = df.values.tolist()
    headers = df.columns.tolist()
    return write_csv(data, headers, output_path)

def append_csv(data, output_path):
    """Append rows (without headers) to an existing CSV."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(data)
    return output_path
