
data = [
    ["CVE-1", "Desc", "2023-01-01", "10.0"],
    ["CVE-2", "Desc", "2023-01-02", "N/A"],
    ["CVE-3", "Desc", "2023-01-03", "5.0"]
]

def get_score_value(row):
    try:
        return float(row[3])
    except (ValueError, IndexError):
        return -1.0

# Sort Descending (High to Low)
data.sort(key=get_score_value, reverse=True)
print("Sorted Desc:", [x[3] for x in data])

# Sort Ascending (Low to High)
data.sort(key=get_score_value, reverse=False)
print("Sorted Asc:", [x[3] for x in data])
