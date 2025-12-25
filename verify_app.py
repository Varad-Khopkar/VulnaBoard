import requests
import threat_knowledge_base
import osint_scanner
import os

print("=== VERIFICATION STARTED ===\n")

# 1. Verify DB Init and Seeding
print("[1] Verifying Database...")
if os.path.exists("threat_intel.db"):
    print("[OK] DB file exists.")
else:
    print("[FAIL] DB file missing! (Will be created on app start)")

# Manually verify seed logic
threat_knowledge_base.init_db()
count = threat_knowledge_base.import_from_csv('seed_threats.csv')
print(f"[OK] Imported/Verified {count} seed items.")

# 2. Verify Hash Lookup
print("\n[2] Verifying Hash Lookup (WannaCry)...")
wc_hash = "84c82835a5d21bbcf75a61706d8ab549"
threat = threat_knowledge_base.get_threat(wc_hash)
if threat and threat['name'] == 'WannaCry':
    print(f"[OK] Found Threat: {threat['name']} - {threat['related_cves']}")
else:
    print("[FAIL] Failed to find WannaCry hash in DB.")

# 3. Verify OSINT Scanner (Network Check)
print("\n[3] Verifying OSINT Scanner (DuckDuckGo)...")
try:
    # Use a well-known hash: Log4j CVE test
    # This might fail if network is blocked or rate-limited
    res = osint_scanner.scan_web("CVE-2021-44228") # Searching for CVE itself often brings up the CVE page with the ID
    # Better test: Search for a hash known to be associated with a CVE
    # Let's search for WannaCry hash again to see if it finds MS17-010 or CVE-2017-0144
    cves = osint_scanner.scan_web(wc_hash)
    print(f"[INFO] OSINT found: {cves}")
    if len(cves) > 0:
        print("[OK] OSINT Scanner is working and returning data.")
    else:
        print("[WARN] OSINT Scanner ran but found no CVEs. (Expected if search engine blocks request or no good results)")
except Exception as e:
    print(f"[FAIL] OSINT Scanner crashed: {e}")

print("\n=== VERIFICATION COMPLETE ===")
