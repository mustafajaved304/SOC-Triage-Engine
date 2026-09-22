import os
import json
import re
import sqlite3
import requests
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from flasgger import Swagger
from colorama import Fore, Style, init

init(autoreset=True)

app = Flask(__name__)
app.config['SWAGGER'] = {
    'title': 'Enterprise SOC & DevSecOps API',
    'uiversion': 3
}
swagger = Swagger(app)

AUTHOR = "Mustafa Mehmood Javed"
DB_NAME = "soc_platform.db"

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS raw_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_id INTEGER,
            user TEXT,
            source_ip TEXT,
            process_name TEXT,
            target_user TEXT,
            raw_data TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            title TEXT,
            severity TEXT,
            risk_score INTEGER,
            details TEXT,
            source_ip TEXT,
            mitre_techniques TEXT,
            playbook TEXT,
            intel TEXT,
            status TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            incident_id TEXT,
            action TEXT,
            analyst TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ti_cache (
            ip TEXT PRIMARY KEY,
            abuse_score INTEGER,
            vt_score INTEGER,
            consensus_score INTEGER,
            country TEXT,
            isp TEXT,
            cached_at TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS watchlist (
            ioc_value TEXT PRIMARY KEY,
            ioc_type TEXT,
            reason TEXT,
            added_at TEXT
        )
    ''')

    conn.commit()
    conn.close()

init_db()

ASSET_WEIGHTS = {
    "192.168.1.50": {"name": "Domain Controller", "multiplier": 1.5},
    "192.168.1.100": {"name": "Finance DB Server", "multiplier": 2.0},
    "127.0.0.1": {"name": "Local Host", "multiplier": 1.0}
}

# Reference catalog used to render the MITRE coverage matrix.
# "active" is computed at request time from what's actually in the incidents table.
MITRE_CATALOG = [
    {"code": "T1110",       "name": "Brute Force",           "tactic": "Credential Access"},
    {"code": "T1003.001",   "name": "LSASS Memory",          "tactic": "Credential Access"},
    {"code": "T1552.001",   "name": "Credentials In Files",  "tactic": "Credential Access"},
    {"code": "T1136.001",   "name": "Local Account",         "tactic": "Persistence"},
    {"code": "T1053",       "name": "Scheduled Task",        "tactic": "Persistence"},
    {"code": "T1059.001",   "name": "PowerShell",            "tactic": "Execution"},
    {"code": "T1078",       "name": "Valid Accounts",        "tactic": "Defense Evasion"},
    {"code": "T1071",       "name": "App Layer Protocol",    "tactic": "Command & Control"},
]

# --- THREAT INTEL & DETECTIONS ---
def query_threat_intel(ip):
    if ip in ["127.0.0.1", "192.168.1.50", "192.168.1.100"]:
        return {"abuse_score": 0, "vt_score": 0, "consensus": 0, "country": "INTERNAL", "isp": "Private LAN"}

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT abuse_score, vt_score, consensus_score, country, isp FROM ti_cache WHERE ip = ?", (ip,))
    cached = cursor.fetchone()

    if cached:
        conn.close()
        return {"abuse_score": cached[0], "vt_score": cached[1], "consensus": cached[2], "country": cached[3], "isp": cached[4]}

    if ip == "185.220.101.5":
        abuse_score, vt_score, country, isp = 98, 85, "DE (Germany)", "Tor Exit Node Network"
    else:
        abuse_score, vt_score, country, isp = 15, 10, "US (United States)", "Commercial ISP"

    consensus = int((abuse_score + vt_score) / 2)
    cursor.execute('INSERT OR REPLACE INTO ti_cache VALUES (?, ?, ?, ?, ?, ?, ?)',
                   (ip, abuse_score, vt_score, consensus, country, isp, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

    return {"abuse_score": abuse_score, "vt_score": vt_score, "consensus": consensus, "country": country, "isp": isp}

def run_detection_pipeline(logs):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT ioc_value FROM watchlist")
    watchlist_iocs = [row[0] for row in cursor.fetchall()]

    ip_events = {}
    for log in logs:
        ip = log.get("source_ip", "127.0.0.1")
        ip_events.setdefault(ip, []).append(log)

    incidents = []
    for ip, events in ip_events.items():
        event_ids = [e.get("event_id") for e in events]
        asset_info = ASSET_WEIGHTS.get(ip, {"name": "Standard Workstation", "multiplier": 1.0})
        ti_data = query_threat_intel(ip)
        is_watchlist_hit = ip in watchlist_iocs

        if 4625 in event_ids and 4720 in event_ids:
            base_risk = 100 if is_watchlist_hit else 85
            final_risk = int(base_risk * asset_info["multiplier"])
            incidents.append({
                "id": f"CAMP-{int(datetime.now().timestamp())}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "title": f"Attack chain: brute force then persistence {'[WATCHLIST]' if is_watchlist_hit else ''}",
                "severity": "CRITICAL",
                "risk_score": min(final_risk, 100),
                "details": f"Correlated attack campaign on {asset_info['name']} ({ip}).",
                "source_ip": ip,
                "mitre_techniques": "T1110, T1136.001",
                "playbook": "1. Isolate host immediately.<br>2. Block source IP.<br>3. Reset domain accounts.",
                "intel": f"TI consensus {ti_data['consensus']}% &middot; {ti_data['country']}",
                "status": "OPEN"
            })
            continue

        for idx, event in enumerate(events):
            eid = event.get("event_id")
            proc = event.get("process_name", "")

            if eid in [10, 4656] and "lsass.exe" in proc.lower():
                final_risk = int(90 * asset_info["multiplier"])
                incidents.append({
                    "id": f"INC-LSASS-{idx+100}",
                    "timestamp": event.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    "title": "Credential dumping: LSASS access",
                    "severity": "CRITICAL",
                    "risk_score": min(final_risk, 100),
                    "details": f"Target process lsass.exe accessed by {event.get('user')}",
                    "source_ip": ip,
                    "mitre_techniques": "T1003.001",
                    "playbook": "1. Dump host memory.<br>2. Force password resets.",
                    "intel": f"Asset: {asset_info['name']}",
                    "status": "OPEN"
                })

    for inc in incidents:
        cursor.execute('''
            INSERT OR REPLACE INTO incidents
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (inc["id"], inc["timestamp"], inc["title"], inc["severity"],
              inc["risk_score"], inc["details"], inc["source_ip"],
              inc["mitre_techniques"], inc["playbook"], inc["intel"], inc["status"]))

    conn.commit()
    conn.close()

def build_mitre_matrix(incidents):
    """Marks catalog techniques active/inactive based on what's actually in the incident table."""
    active_codes = set()
    for inc in incidents:
        raw = inc[7] or ""
        for part in re.split(r"[,>\->]+", raw):
            code = part.strip()
            if code:
                active_codes.add(code)

    matrix = []
    for t in MITRE_CATALOG:
        matrix.append({**t, "active": t["code"] in active_codes})

    covered = sum(1 for t in matrix if t["active"])
    coverage_pct = int((covered / len(matrix)) * 100) if matrix else 0
    return matrix, coverage_pct

# --- FRONTEND TEMPLATE ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SOC Console &middot; {{ author }}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg: #0b0f17;
            --surface: #121826;
            --border: #232c40;
            --text: #e7ebf3;
            --text-muted: #8a93a8;
            --text-faint: #5b6478;
            --accent: #37d6c4;
            --accent-dim: #1c4b47;
            --critical: #ef4a5f;
            --high: #f5a524;
            --success: #34d399;
        }

        * { box-sizing: border-box; }
        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: 'IBM Plex Sans', -apple-system, sans-serif;
            font-size: 14.5px;
        }
        .mono { font-family: 'IBM Plex Mono', monospace; }

        /* ---- Header ---- */
        .topbar {
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 14px 28px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .brand { display: flex; align-items: center; gap: 10px; }
        .brand .pulse {
            width: 8px; height: 8px; border-radius: 50%;
            background: var(--accent);
            box-shadow: 0 0 0 0 rgba(55,214,196,0.55);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%   { box-shadow: 0 0 0 0 rgba(55,214,196,0.5); }
            70%  { box-shadow: 0 0 0 8px rgba(55,214,196,0); }
            100% { box-shadow: 0 0 0 0 rgba(55,214,196,0); }
        }
        .brand-title { font-weight: 600; font-size: 1.02rem; }
        .brand-sub { color: var(--text-muted); font-size: 0.78rem; margin-left: 2px; }
        .topbar-right { display: flex; align-items: center; gap: 10px; }
        .pill {
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 5px 11px;
            border-radius: 5px;
            font-size: 0.78rem;
            text-decoration: none;
        }
        .pill:hover { border-color: var(--accent); color: var(--accent); }
        .author-pill {
            border: 1px solid var(--accent-dim);
            background: rgba(55,214,196,0.06);
            color: var(--accent);
            padding: 5px 12px;
            border-radius: 5px;
            font-size: 0.78rem;
            font-weight: 500;
        }

        /* ---- Tabs ---- */
        .tabbar {
            display: flex;
            gap: 2px;
            padding: 0 28px;
            background: var(--surface);
            border-bottom: 1px solid var(--border);
        }
        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-family: 'IBM Plex Sans', sans-serif;
            font-size: 0.86rem;
            font-weight: 500;
            padding: 12px 16px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
        }
        .tab-btn .count {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.7rem;
            color: var(--text-faint);
            margin-left: 5px;
        }
        .tab-btn:hover { color: var(--text); }
        .tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
        .tab-btn.active .count { color: var(--accent); }

        .shell { padding: 24px 28px 44px; max-width: 1280px; margin: 0 auto; }
        .tab-panel { display: none; }
        .tab-panel.active { display: block; }

        /* ---- Metrics strip (Overview) ---- */
        .metrics-strip {
            display: flex;
            border: 1px solid var(--border);
            border-radius: 6px;
            background: var(--surface);
            margin-bottom: 20px;
            overflow: hidden;
        }
        .metric { flex: 1; padding: 16px 20px; border-right: 1px solid var(--border); }
        .metric:last-child { border-right: none; }
        .metric-value { font-family: 'IBM Plex Mono', monospace; font-size: 1.55rem; font-weight: 600; line-height: 1; }
        .metric-label { color: var(--text-muted); font-size: 0.75rem; margin-top: 6px; }
        .metric-value.critical { color: var(--critical); }
        .metric-value.accent { color: var(--accent); }

        .panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 18px 20px;
            margin-bottom: 20px;
        }
        .panel-title {
            font-size: 0.92rem;
            font-weight: 600;
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .panel-title .hint { color: var(--text-faint); font-weight: 400; font-size: 0.76rem; }

        .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        @media (max-width: 860px) { .two-col { grid-template-columns: 1fr; } }

        .recent-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 9px 0;
            border-bottom: 1px solid var(--border);
            font-size: 0.82rem;
        }
        .recent-row:last-child { border-bottom: none; }

        /* ---- Ingestion ---- */
        textarea.log-input {
            width: 100%;
            background: var(--bg);
            color: var(--accent);
            border: 1px solid var(--border);
            border-radius: 5px;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.84rem;
            padding: 12px;
            resize: vertical;
        }
        textarea.log-input:focus { outline: none; border-color: var(--accent); }
        .btn-console {
            background: var(--accent);
            color: #06231f;
            border: none;
            font-weight: 600;
            font-size: 0.85rem;
            padding: 9px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 12px;
        }
        .btn-console:hover { background: #4ee8d5; }

        /* ---- Table ---- */
        table.console-table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
        table.console-table th {
            text-align: left;
            color: var(--text-faint);
            font-weight: 500;
            font-size: 0.72rem;
            padding: 8px 10px;
            border-bottom: 1px solid var(--border);
        }
        table.console-table td {
            padding: 12px 10px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }
        table.console-table tr:last-child td { border-bottom: none; }
        .inc-id { color: var(--text-muted); }
        .inc-title { font-weight: 500; margin-bottom: 6px; }

        .sev-tag {
            display: inline-block;
            font-size: 0.68rem;
            font-weight: 600;
            padding: 2px 7px;
            border-radius: 4px;
        }
        .sev-CRITICAL { background: rgba(239,74,95,0.14); color: var(--critical); border: 1px solid rgba(239,74,95,0.35); }
        .sev-HIGH { background: rgba(245,165,36,0.14); color: var(--high); border: 1px solid rgba(245,165,36,0.35); }

        .risk-track { width: 74px; height: 5px; background: var(--border); border-radius: 3px; overflow: hidden; margin-top: 6px; }
        .risk-fill { height: 100%; border-radius: 3px; }
        .risk-num { font-family: 'IBM Plex Mono', monospace; font-weight: 600; }

        .mitre-chip {
            display: inline-block;
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.7rem;
            color: var(--accent);
            border: 1px solid var(--accent-dim);
            background: rgba(55,214,196,0.05);
            padding: 1px 6px;
            border-radius: 4px;
            margin: 2px 3px 0 0;
        }

        .playbook-box {
            background: var(--bg);
            border-left: 2px solid var(--accent);
            padding: 8px 10px;
            font-size: 0.78rem;
            color: var(--text-muted);
            line-height: 1.55;
            border-radius: 0 4px 4px 0;
        }

        .status-tag {
            font-family: 'IBM Plex Mono', monospace;
            font-size: 0.7rem;
            padding: 3px 8px;
            border-radius: 4px;
            border: 1px solid var(--border);
            color: var(--text-muted);
        }
        .status-tag.resolved { color: var(--success); border-color: rgba(52,211,153,0.35); }

        .action-row { display: flex; gap: 6px; flex-wrap: wrap; }
        .btn-ghost {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 0.72rem;
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
        }
        .btn-ghost.ack:hover { border-color: var(--high); color: var(--high); }
        .btn-ghost.isolate:hover { border-color: var(--critical); color: var(--critical); }
        .btn-ghost.close:hover { border-color: var(--success); color: var(--success); }

        .empty-state { text-align: center; padding: 30px 10px; color: var(--text-faint); font-size: 0.85rem; }

        /* ---- MITRE matrix ---- */
        .mitre-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }
        @media (max-width: 700px) { .mitre-grid { grid-template-columns: 1fr; } }
        .mitre-row {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 12px;
            border: 1px solid var(--border);
            border-radius: 5px;
            background: var(--bg);
        }
        .mitre-row.on { border-color: rgba(239,74,95,0.4); background: rgba(239,74,95,0.06); }
        .mitre-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--text-faint); flex-shrink: 0; }
        .mitre-row.on .mitre-dot { background: var(--critical); }
        .mitre-code { font-family: 'IBM Plex Mono', monospace; font-size: 0.8rem; color: var(--text); }
        .mitre-name { font-size: 0.73rem; color: var(--text-muted); }
        .mitre-tactic { margin-left: auto; font-size: 0.66rem; color: var(--text-faint); text-align: right; }

        .coverage-bar { height: 5px; background: var(--border); border-radius: 3px; overflow: hidden; margin: 10px 0 16px; }
        .coverage-fill { height: 100%; background: var(--accent); }
    </style>
</head>
<body>

    <div class="topbar">
        <div class="brand">
            <span class="pulse"></span>
            <span class="brand-title">SOC Console</span>
            <span class="brand-sub">hybrid on-prem + cloud triage</span>
        </div>
        <div class="topbar-right">
            <span class="pill">&#128230; docker-ready</span>
            <a href="/apidocs" target="_blank" class="pill">API docs</a>
            <span class="author-pill">{{ author }} &middot; BS Cyber Security</span>
        </div>
    </div>

    <div class="tabbar">
        <button class="tab-btn active" data-tab="overview">Overview</button>
        <button class="tab-btn" data-tab="incidents">Incident Queue <span class="count">{{ metrics.total }}</span></button>
        <button class="tab-btn" data-tab="ingest">Log Ingestion</button>
        <button class="tab-btn" data-tab="mitre">ATT&amp;CK Matrix <span class="count">{{ mitre_coverage }}%</span></button>
    </div>

    <div class="shell">

        <!-- OVERVIEW -->
        <div class="tab-panel active" id="tab-overview">
            <div class="metrics-strip">
                <div class="metric">
                    <div class="metric-value critical">{{ metrics.campaigns }}</div>
                    <div class="metric-label">Correlated campaigns</div>
                </div>
                <div class="metric">
                    <div class="metric-value critical">{{ metrics.critical }}</div>
                    <div class="metric-label">Critical alerts</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{{ metrics.total }}</div>
                    <div class="metric-label">Total incidents logged</div>
                </div>
                <div class="metric">
                    <div class="metric-value accent">{{ mitre_coverage }}%</div>
                    <div class="metric-label">ATT&amp;CK technique coverage</div>
                </div>
            </div>

            <div class="two-col">
                <div class="panel">
                    <div class="panel-title">Severity breakdown</div>
                    <canvas id="severityChart" height="190"></canvas>
                </div>
                <div class="panel">
                    <div class="panel-title">
                        Most recent incidents
                        <span class="hint">top 5 by risk</span>
                    </div>
                    {% if incidents %}
                        {% for inc in incidents[:5] %}
                        <div class="recent-row">
                            <div>
                                <div style="font-weight:500;">{{ inc[2] }}</div>
                                <span class="sev-tag sev-{{ inc[3] }}">{{ inc[3] }}</span>
                            </div>
                            <span class="risk-num">{{ inc[4] }}</span>
                        </div>
                        {% endfor %}
                    {% else %}
                        <div class="empty-state">No incidents yet &mdash; head to Log Ingestion to run detection.</div>
                    {% endif %}
                </div>
            </div>
        </div>

        <!-- INCIDENT QUEUE -->
        <div class="tab-panel" id="tab-incidents">
            <div class="panel">
                <div class="panel-title">
                    Incident queue
                    <span class="hint">sorted by risk score</span>
                </div>
                {% if incidents %}
                <div class="table-responsive">
                    <table class="console-table">
                        <thead>
                            <tr>
                                <th>Incident</th>
                                <th>Risk</th>
                                <th>MITRE &amp; intel</th>
                                <th>Response playbook</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for inc in incidents %}
                            <tr>
                                <td style="min-width:220px;">
                                    <div class="inc-title">{{ inc[2] }}</div>
                                    <span class="sev-tag sev-{{ inc[3] }}">{{ inc[3] }}</span>
                                    <div class="inc-id mono mt-2">{{ inc[0] }}</div>
                                    <div class="mono" style="color: var(--text-faint); font-size: 0.72rem;">{{ inc[6] }}</div>
                                </td>
                                <td style="min-width:80px;">
                                    <span class="risk-num">{{ inc[4] }}</span>
                                    <div class="risk-track">
                                        <div class="risk-fill" style="width: {{ inc[4] }}%; background: {{ '#ef4a5f' if inc[4] >= 70 else '#f5a524' }};"></div>
                                    </div>
                                </td>
                                <td style="min-width:200px;">
                                    {% for code in inc[7].split(',') %}
                                    <span class="mitre-chip">{{ code.strip() }}</span>
                                    {% endfor %}
                                    <div class="mt-2" style="color: var(--text-muted); font-size: 0.76rem;">{{ inc[9] | safe }}</div>
                                </td>
                                <td style="min-width:200px;">
                                    <div class="playbook-box">{{ inc[8] | safe }}</div>
                                </td>
                                <td style="min-width:100px;">
                                    <span class="status-tag {{ 'resolved' if inc[10] == 'RESOLVED' else '' }}" id="status-{{ inc[0] }}">{{ inc[10] }}</span>
                                </td>
                                <td style="min-width:110px;">
                                    <div class="action-row">
                                        <button class="btn-ghost ack" onclick="updateStatus('{{ inc[0] }}', 'ACKNOWLEDGED')">Ack</button>
                                        <button class="btn-ghost isolate" onclick="updateStatus('{{ inc[0] }}', 'CONTAINED')">Isolate</button>
                                        <button class="btn-ghost close" onclick="updateStatus('{{ inc[0] }}', 'RESOLVED')">Close</button>
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="empty-state">No incidents yet &mdash; paste a log stream in Log Ingestion and run detection.</div>
                {% endif %}
            </div>
        </div>

        <!-- INGESTION -->
        <div class="tab-panel" id="tab-ingest">
            <div class="panel">
                <div class="panel-title">
                    Log ingestion
                    <span class="hint">Windows syslog &middot; CloudTrail JSON &middot; CI/CD YAML</span>
                </div>
                <form method="POST" action="/ingest">
                    <textarea class="log-input" name="raw_logs" rows="6" placeholder='[{"event_id": 4625, "source_ip": "185.220.101.5", "user": "admin"}, ...]'></textarea>
                    <br>
                    <button type="submit" class="btn-console">Run detection</button>
                </form>
            </div>
        </div>

        <!-- MITRE MATRIX -->
        <div class="tab-panel" id="tab-mitre">
            <div class="panel">
                <div class="panel-title">MITRE ATT&amp;CK coverage</div>
                <div class="coverage-bar"><div class="coverage-fill" style="width: {{ mitre_coverage }}%;"></div></div>
                <div class="mitre-grid">
                    {% for t in mitre_matrix %}
                    <div class="mitre-row {{ 'on' if t.active else '' }}">
                        <span class="mitre-dot"></span>
                        <div>
                            <div class="mitre-code">{{ t.code }}</div>
                            <div class="mitre-name">{{ t.name }}</div>
                        </div>
                        <span class="mitre-tactic">{{ t.tactic }}</span>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>

    </div>

    <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Other'],
                datasets: [{
                    data: [{{ metrics.critical }}, {{ metrics.high }}, {{ metrics.total - metrics.critical - metrics.high }}],
                    backgroundColor: ['#ef4a5f', '#f5a524', '#232c40'],
                    borderWidth: 0
                }]
            },
            options: {
                cutout: '70%',
                plugins: { legend: { position: 'bottom', labels: { color: '#8a93a8', boxWidth: 10, font: { size: 11 } } } }
            }
        });

        function updateStatus(incId, newStatus) {
            fetch('/api/incident/action', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ id: incId, status: newStatus, analyst: '{{ author }}' })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    const tag = document.getElementById('status-' + incId);
                    tag.innerText = newStatus;
                    tag.className = 'status-tag' + (newStatus === 'RESOLVED' ? ' resolved' : '');
                }
            });
        }

        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
            });
        });
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def home():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY risk_score DESC")
    incidents = cursor.fetchall()
    conn.close()

    metrics = {
        "total": len(incidents),
        "campaigns": sum(1 for i in incidents if "CAMP-" in i[0]),
        "critical": sum(1 for i in incidents if i[3] == "CRITICAL"),
        "high": sum(1 for i in incidents if i[3] == "HIGH")
    }

    mitre_matrix, mitre_coverage = build_mitre_matrix(incidents)

    return render_template_string(
        HTML_TEMPLATE,
        incidents=incidents,
        metrics=metrics,
        author=AUTHOR,
        mitre_matrix=mitre_matrix,
        mitre_coverage=mitre_coverage
    )

@app.route("/ingest", methods=["POST"])
def ingest():
    raw_data = request.form.get("raw_logs", "").strip()
    if raw_data.startswith("["):
        try:
            logs = json.loads(raw_data)
            run_detection_pipeline(logs)
        except Exception:
            pass
    return home()

@app.route("/api/incident/action", methods=["POST"])
def incident_action():
    """
    Execute Analyst SOAR Action
    ---
    tags:
      - Incident Management
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            id:
              type: string
              example: CAMP-1695420000
            status:
              type: string
              example: CONTAINED
            analyst:
              type: string
              example: Mustafa Mehmood Javed
    responses:
      200:
        description: Action recorded in audit log.
    """
    data = request.json
    inc_id = data.get("id")
    new_status = data.get("status")
    analyst = data.get("analyst", "Mustafa Mehmood Javed")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE incidents SET status = ? WHERE id = ?", (new_status, inc_id))
    cursor.execute("INSERT INTO audit_logs (timestamp, incident_id, action, analyst) VALUES (?, ?, ?, ?)",
                   (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), inc_id, f"Status updated to {new_status}", analyst))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "status": new_status})

if __name__ == "__main__":
    print(f"\n{Fore.GREEN}=== Enterprise SOC Phase 3 Engine Active ===")
    print(f"{Fore.CYAN}Architect: {Style.BRIGHT}{AUTHOR}")
    print(f"{Fore.YELLOW}Local Endpoint: http://127.0.0.1:5000")
    print(f"{Fore.MAGENTA}Swagger OpenAPI Docs: http://127.0.0.1:5000/apidocs\n")
    app.run(debug=True, port=5000)