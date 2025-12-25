import requests
import re
import urllib.parse

def scan_web(hash_str):
    """
    Scans public search engine results for the given hash to find associated CVEs.
    Returns a list of unique CVE IDs found.
    """
    cves = set()
    
    # We will search for "Hash CVE" to find pages linking the two
    query = f"{hash_str} CVE"
    encoded_query = urllib.parse.quote(query)
    
    # Using DuckDuckGo HTML (Lite) version to avoid heavy JS and captchas
    # Note: This is a basic scraper and might be rate-limited.
    url = f"https://html.duckduckgo.com/html/?q={encoded_query}"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            content = response.text
            # Regex to find CVE-YYYY-NNNN+
            # Matches CVE-2021-44228, CVE-2017-0144, etc.
            found = re.findall(r'CVE-\d{4}-\d{4,}', content, re.IGNORECASE)
            for cve in found:
                cves.add(cve.upper())
                
    except Exception as e:
        print(f"OSINT Scan Error: {e}")

    return list(cves)

if __name__ == "__main__":
    # Test with WannaCry Hash
    wc_hash = "84c82835a5d21bbcf75a61706d8ab549" # WannaCry MD5
    print(f"Scanning for {wc_hash}...")
    results = scan_web(wc_hash)
    print(f"Found CVEs: {results}")
