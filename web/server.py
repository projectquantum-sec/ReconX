#!/usr/bin/env python3
"""
ReconX Local Web UI & REST Server
Provides an interactive web dashboard and API to view targets, inspect findings, and trigger scans.
"""

import os
import sys
import json
import glob
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconX v2.0 - Security Operations Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0b0f19;
            --bg-card: rgba(18, 24, 38, 0.7);
            --border: rgba(255, 255, 255, 0.08);
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.15);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --danger: #f43f5e;
            --success: #10b981;
            --warning: #f59e0b;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            padding: 2rem;
            min-height: 100vh;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }
        .header h1 {
            font-size: 1.75rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        .header h1 span { color: var(--accent); }
        .grid {
            display: grid;
            grid-template-columns: 350px 1fr;
            gap: 1.5rem;
        }
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(12px);
        }
        .card h2 {
            font-size: 1.1rem;
            margin-bottom: 1rem;
            color: var(--accent);
            display: flex;
            justify-content: space-between;
        }
        .target-list {
            list-style: none;
            max-height: 600px;
            overflow-y: auto;
        }
        .target-item {
            padding: 0.85rem 1rem;
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            margin-bottom: 0.5rem;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .target-item:hover, .target-item.active {
            background: var(--accent-glow);
            border-color: var(--accent);
        }
        .btn {
            background: var(--accent);
            color: #000;
            font-weight: 600;
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            border: none;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }
        .scan-form input, .scan-form select {
            width: 100%;
            padding: 0.75rem;
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border);
            border-radius: 6px;
            color: #fff;
            margin-bottom: 0.75rem;
            font-family: inherit;
        }
        pre {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0, 0, 0, 0.4);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 0.85rem;
            color: #38bdf8;
            max-height: 550px;
        }
        .badge {
            font-size: 0.75rem;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            background: rgba(56, 189, 248, 0.2);
            color: var(--accent);
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Recon<span>X</span> Dashboard</h1>
        <div style="display: flex; gap: 1rem; align-items: center;">
            <span class="badge">v2.0 Active</span>
            <button class="btn" onclick="fetchTargets()">↻ Refresh Targets</button>
        </div>
    </div>
    <div class="grid">
        <div style="display: flex; flex-direction: column; gap: 1.5rem;">
            <div class="card">
                <h2>🚀 Launch New Scan</h2>
                <div class="scan-form">
                    <input type="text" id="targetInput" placeholder="Target domain (e.g., example.com)" />
                    <select id="robustnessSelect">
                        <option value="1">Level 1 - Quick (Rapid)</option>
                        <option value="2">Level 2 - Light</option>
                        <option value="3" selected>Level 3 - Normal (Default)</option>
                        <option value="4">Level 4 - Thorough</option>
                        <option value="5">Level 5 - Aggressive</option>
                    </select>
                    <button class="btn" style="width:100%" onclick="launchScan()">Start Reconnaissance</button>
                </div>
            </div>
            <div class="card">
                <h2>🎯 Scanned Targets <span id="targetCount" class="badge">0</span></h2>
                <ul class="target-list" id="targetList"></ul>
            </div>
        </div>
        <div class="card">
            <h2 id="viewTitle">Target Inspection</h2>
            <pre id="outputView">Select a target from the left to view reports and intelligence summary.</pre>
        </div>
    </div>
    <script>
        async function fetchTargets() {
            try {
                const res = await fetch('/api/targets');
                const targets = await res.json();
                document.getElementById('targetCount').innerText = targets.length;
                const list = document.getElementById('targetList');
                list.innerHTML = '';
                targets.forEach(t => {
                    const li = document.createElement('li');
                    li.className = 'target-item';
                    li.innerHTML = `<span>${t}</span><span class="badge">Inspect</span>`;
                    li.onclick = () => loadTarget(t);
                    list.appendChild(li);
                });
            } catch(e) { console.error(e); }
        }
        async function loadTarget(t) {
            document.querySelectorAll('.target-item').forEach(el => el.classList.remove('active'));
            document.getElementById('viewTitle').innerText = 'Intelligence Summary: ' + t;
            const res = await fetch('/api/report/' + encodeURIComponent(t));
            const data = await res.json();
            document.getElementById('outputView').innerText = JSON.stringify(data, null, 2);
        }
        async function launchScan() {
            const target = document.getElementById('targetInput').value.trim();
            const level = document.getElementById('robustnessSelect').value;
            if(!target) return alert('Enter a target domain!');
            document.getElementById('outputView').innerText = 'Starting scan for ' + target + '...';
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ target, robustness: level })
            });
            const data = await res.json();
            alert(data.message || 'Scan launched in background!');
            fetchTargets();
        }
        fetchTargets();
    </script>
</body>
</html>"""

class ReconXHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif parsed.path == "/api/targets":
            targets = []
            if os.path.exists(OUTPUT_DIR):
                for item in os.listdir(OUTPUT_DIR):
                    if os.path.isdir(os.path.join(OUTPUT_DIR, item)):
                        targets.append(item)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(sorted(targets)).encode("utf-8"))
        elif parsed.path.startswith("/api/report/"):
            target = parsed.path.replace("/api/report/", "")
            target_dir = os.path.join(OUTPUT_DIR, target)
            data = {"target": target, "subdomains": [], "ports": [], "vulnerabilities": []}
            
            subs_file = os.path.join(target_dir, "passive", "subdomains.txt")
            if os.path.exists(subs_file):
                with open(subs_file, "r") as f:
                    data["subdomains"] = [l.strip() for l in f if l.strip()][:200]
            
            ports_file = os.path.join(target_dir, "active", "ports_open.txt")
            if os.path.exists(ports_file):
                with open(ports_file, "r") as f:
                    data["ports"] = [l.strip() for l in f if l.strip()][:100]
                    
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            target = body.get("target")
            robustness = body.get("robustness", "3")
            
            if target:
                script = os.path.join(BASE_DIR, "reconx.sh")
                subprocess.Popen(["bash", script, "-t", target, "-r", str(robustness), "--full"], cwd=BASE_DIR)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success", "message": f"Scan initiated for {target}"}).encode("utf-8"))
            else:
                self.send_response(400)
                self.end_headers()

def run_server(port=8000):
    server = HTTPServer(("0.0.0.0", port), ReconXHandler)
    print(f"[*] ReconX Web Dashboard serving at http://127.0.0.1:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port)
