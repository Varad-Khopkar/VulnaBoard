import requests
import json
import csv
import os
from datetime import datetime

# Constants
# Using NVD API 2.0
# resultsPerPage=50 to get a quick snapshot of data
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=50'
OUTPUT_FILE = 'critical_cves.csv'
TIMESTAMP_FILE = 'last_updated.txt'

def download_feed():
    """Download data from NVD API 2.0."""
    headers = {
        'User-Agent': 'VulnaBoard-App/1.0',
    }
    response = requests.get(NVD_API_URL, headers=headers, timeout=30)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch from NVD API: {response.status_code}")
    
    return response.json()

def parse_feed(json_data):
    all_cves = []
    
    # API 2.0 Structure: {'vulnerabilities': [{'cve': {...}}, ...]}
    vulnerabilities = json_data.get("vulnerabilities", [])
    
    for item in vulnerabilities:
        cve_obj = item.get("cve", {})
        
        cve_id = cve_obj.get("id")
        
        # Descriptions
        descriptions = cve_obj.get("descriptions", [])
        description = "No description available."
        # Prefer English description
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value")
                break
        
        published_date = cve_obj.get("published", "")
        
        # Metrics / Scores
        # V3.1 is preferred, then V3.0, then V2
        score = "N/A"
        metrics = cve_obj.get("metrics", {})
        
        if "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

        all_cves.append([cve_id, description, published_date, score])
        
    return all_cves

def save_to_csv(new_data, filename):
    existing_ids = set()

    # Load existing CVE IDs
    if os.path.exists(filename):
        with open(filename, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip header
            for row in reader:
                if row:
                    existing_ids.add(row[0])  # CVE ID

    # Filter out already existing CVEs
    unique_data = [row for row in new_data if row[0] not in existing_ids]

    # Append only new CVEs
    write_header = not os.path.exists(filename)
    with open(filename, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["CVE ID", "Description", "Published Date", "CVSS v3.1 Score"])
        writer.writerows(unique_data)

    return len(unique_data)

def load_csv(filename):
    """Load CSV data to display in UI."""
    if not os.path.exists(filename):
        return []
    with open(filename, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        try:
            next(reader, None)  # Skip header
        except StopIteration:
            pass
        return list(reader)

def save_last_updated():
    """Save the timestamp of the last CVE fetch."""
    with open(TIMESTAMP_FILE, 'w') as f:
        f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

def load_last_updated():
    """Load the last updated timestamp if available."""
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE, 'r') as f:
            return f.read().strip()
    return "Never"

def run_tracker():
    try:
        data = download_feed()
        results = parse_feed(data)
        new_count = save_to_csv(results, OUTPUT_FILE)
        save_last_updated()
        return f"[SUCCESS] {new_count} new CVEs added via NVD API."
    except Exception as e:
        return f"[ERROR] Failed to fetch data: {e}"
