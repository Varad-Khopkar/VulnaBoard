from flask import Flask, render_template, redirect, url_for, flash, request
import cve_engine
import threat_knowledge_base
import osint_scanner
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Initialize DB on start
threat_knowledge_base.init_db()
# Seed DB if empty
if threat_knowledge_base.import_from_csv('seed_threats.csv') > 0:
    print("Seeded database with initial threats.")

# ======================== Flask Routes ========================

@app.route('/', methods=['GET'])
def index():
    query = request.args.get('q', '').lower()
    year_filter = request.args.get('year', '')
    
    # Advanced Table Params
    try:
        page = int(request.args.get('page', 1))
    except ValueError:
        page = 1
        
    try:
        per_page = int(request.args.get('per_page', 10))
    except ValueError:
        per_page = 10
        
    sort_by = request.args.get('sort', 'date') # date | score
    sort_order = request.args.get('order', 'desc') # asc | desc

    # Load data from the separated engine
    # Returns list of [CVE_ID, Desc, Date, Score]
    all_cves = cve_engine.load_csv(cve_engine.OUTPUT_FILE)
    last_updated = cve_engine.load_last_updated()

    # Filtering
    if query:
        all_cves = [row for row in all_cves if query in row[1].lower() or query in row[0].lower()]

    if year_filter:
        all_cves = [row for row in all_cves if len(row) > 2 and row[2][:4] == year_filter]

    # Helper for CVSS Score sorting (handle N/A)
    def get_score_value(row):
        try:
            # Row index 3 is score
            return float(row[3])
        except (ValueError, IndexError):
            return -1.0 # Treat N/A as lowest

    # Sorting Logic
    if sort_by == 'score':
        all_cves.sort(key=get_score_value, reverse=(sort_order == 'desc'))
    else:
        # Sort by Date (Row index 2)
        all_cves.sort(key=lambda x: x[2] if len(x) > 2 else "", reverse=(sort_order == 'desc'))

    # Pagination
    total = len(all_cves)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_cves = all_cves[start:end]
    total_pages = (total + per_page - 1) // per_page
    
    # Ensure page valid
    if page > total_pages and total_pages > 0:
        page = total_pages
        start = (page - 1) * per_page
        paginated_cves = all_cves[start:start + per_page]

    return render_template(
        "index.html",
        cves=paginated_cves,
        last_updated=last_updated,
        query=query,
        page=page,
        total_pages=total_pages,
        sort_by=sort_by,
        sort_order=sort_order,
        per_page=per_page,
        year_filter=year_filter,
        total_items=total
    )

@app.route('/refresh')
def refresh():
    message = cve_engine.run_tracker()
    flash(message)
    return redirect(url_for('index'))

@app.route('/analyze', methods=['POST'])
def analyze():
    hash_input = request.form.get('hash', '').strip()
    if not hash_input:
        flash("Please enter a valid hash.")
        return redirect(url_for('index'))
    
    # Check Local DB
    threat = threat_knowledge_base.get_threat(hash_input)
    
    if threat:
        return render_template('report.html', threat=threat)
    else:
        # Not found, offer to scan? or just show not found
        return render_template('report.html', threat=None, hash=hash_input)

@app.route('/enrich/<hash_str>', methods=['POST'])
def enrich(hash_str):
    # Perform OSINT Scan
    found_cves = osint_scanner.scan_web(hash_str)
    
    if found_cves:
        cve_string = ";".join(found_cves)
        # Add to DB as custom/unknown threat if not exists, or update
        current = threat_knowledge_base.get_threat(hash_str)
        if current:
            # Update existing (logic to merge could be added, for now simple)
            pass 
        else:
            # Create a new entry for this hash found via OSINT
            threat_knowledge_base.add_threat(
                hash_str, 
                "Unknown File", 
                "Suspicious-Web-Scan", 
                "Automatically enriched from public web scan.", 
                cve_string, 
                "Unknown"
            )
        flash(f"OSINT Scan complete! Found: {cve_string}")
    else:
        flash("OSINT Scan completed but found no direct CVE links.")
        
    return redirect(url_for('analyze_get', hash_str=hash_str))

@app.route('/report/<hash_str>', methods=['GET'])
def analyze_get(hash_str):
    threat = threat_knowledge_base.get_threat(hash_str)
    return render_template('report.html', threat=threat, hash=hash_str)

@app.route('/import_feed', methods=['POST'])
def import_feed():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))
    
    if file:
        filepath = os.path.join('uploads', file.filename)
        os.makedirs('uploads', exist_ok=True)
        file.save(filepath)
        count = threat_knowledge_base.import_from_csv(filepath)
        flash(f"Successfully imported {count} threats from {file.filename}")
        os.remove(filepath)
        
    return redirect(url_for('index'))



# ======================== Run Server ========================

if __name__ == "__main__":
    app.run(debug=True)
