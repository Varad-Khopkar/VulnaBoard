# 🛡️ VulnaBoard v2.0: Threat Intelligence Platform

**VulnaBoard** is a self-hosted Threat Intelligence Platform designed for security analysts. It aggregates CVE data from the NVD API, allows for local threat database management, and integrates OSINT scanning to enrich file hashes with vulnerability data.

![VulnaBoard v2.0 Theme](https://i.imgur.com/placeholder.png) 
*(Replace with actual screenshot)*

---

## 🚀 New Features in v2.0

### 🎨 **"Netzon" High-Tech Theme**
-   **Cybersecurity Aesthetic**: Deep Navy environment with Electric Cyan accents (`#64ffda`).
-   **Technical Background**: Custom 40px grid texture for a professional SOC look.
-   **Glassmorphism**: Modern, semi-transparent cards and overlays.
-   **Visual Enhancements**: Replaced emojis with professional Bootstrap Icons.

### 📊 **Advanced Interactive Data Table**
-   **Dynamic Pagination**: User-selectable rows per page (10, 20, 50, 100).
-   **Smart Sorting**: Clickable headers to sort by **Published Date** or **CVSS Score**.
-   **Quick View Modal**: Click any row to open a detailed overlay without leaving the dashboard.
-   **Severity Coloring**:
    -   <span style="color:#ff5f5f; font-weight:bold;">CRITICAL (9.0+)</span>
    -   <span style="color:#ff9800; font-weight:bold;">HIGH (7.0-8.9)</span>
    -   <span style="color:#ffc107; font-weight:bold;">MEDIUM (4.0-6.9)</span>
    -   <span style="color:#4caf50; font-weight:bold;">LOW (<4.0)</span>

### 🕵️ **Threat Intelligence & OSINT**
-   **Hash Analysis**: Search by MD5/SHA256 to check against local threat DB.
-   **OSINT Enrichment**: Triggers a web scan to find `CVE-XXXX-XXXX` references for unknown files.
-   **Threat-to-CVE Linking**: Automatically associates known malware with specific vulnerabilities.

### ⚙️ **Core Engine**
-   **NVD API 2.0 Integrated**: Migrated from legacy JSON feeds to the robust NVD REST API.
-   **Robust Caching**: Local SQLite + CSV caching to minimize API rate limits.
-   **Custom Import**: Upload your own Threat Intelligence CSV feeds.

---

## 🛠️ Installation

```bash
# 1. Clone the repository
git clone https://github.com/Varad-Khopkar/VulnaBoard.git
cd VulnaBoard

# 2. Install Dependencies
pip install -r requirements.txt

# 3. Run the Application
python app.py
```

## 📸 Screenshots

| Dashboard | Analysis Report |
|-----------|----------------|
| *Overview of CVEs with Stats* | *Detailed Threat Breakdown* |

---

## 🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## 📄 License
[MIT](https://choosealicense.com/licenses/mit/)
