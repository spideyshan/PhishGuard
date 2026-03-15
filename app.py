from flask import Flask, render_template, request, jsonify
import sqlite3
import datetime
import os
from detector import analyze_url

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), 'scan_history.db')

# ─── Database setup ───────────────────────────────────────────────────────────
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                url       TEXT    NOT NULL,
                score     INTEGER NOT NULL,
                status    TEXT    NOT NULL,
                scanned_at TEXT   NOT NULL
            )
        ''')
        conn.commit()

init_db()

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/history')
def history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT * FROM scans ORDER BY id DESC LIMIT 200'
        ).fetchall()
    return render_template('history.html', scans=rows)

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
    url = data['url'].strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    result = analyze_url(url)

    # Persist to DB
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            'INSERT INTO scans (url, score, status, scanned_at) VALUES (?,?,?,?)',
            (result['url'], result['score'], result['status'],
             datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()

    return jsonify(result)

@app.route('/api/history')
def api_history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            'SELECT * FROM scans ORDER BY id DESC LIMIT 200'
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/batch_analyze', methods=['POST'])
def batch_analyze():
    data = request.get_json()
    if not data or 'urls' not in data:
        return jsonify({"error": "urls array required"}), 400
    results = []
    for url in data['urls'][:15]:          # Cap at 15 URLs
        url = url.strip()
        if not url:
            continue
        result = analyze_url(url)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                'INSERT INTO scans (url, score, status, scanned_at) VALUES (?,?,?,?)',
                (result['url'], result['score'], result['status'],
                 datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
        results.append(result)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
