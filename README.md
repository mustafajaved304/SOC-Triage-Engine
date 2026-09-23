# 🛡️ Enterprise SOC Triage & DevSecOps Platform

An enterprise-grade, hybrid **Security Operations Center (SOC) Triage Engine, Threat Intelligence Aggregator, and DevSecOps Pipeline Scanner**. Architected to correlate fragmented multi-source log streams (Windows Event Logs, AWS CloudTrail, CI/CD YAML configurations) into unified attack campaigns mapped against the **MITRE ATT&CK® Framework**.

---

## 👨‍💻 System Architect
* **Developer:** Mustafa Mehmood Javed
* **Deployment Target:** Hybrid On-Prem & Cloud SIEM/SOAR Ecosystems

---

## 🌟 Key Architecture & Capabilities

### 1. Multi-Source Stream Ingestion & Parsing
* **Windows Event Ingestion:** Parses Syslog and Security Event logs, tracking critical Security Event IDs (`4625` Brute Force, `4720` Account Creation, `10`/`4656` LSASS Access).
* **AWS CloudTrail JSON Engine:** Extracts unauthorized IAM role assume calls and security group manipulations.
* **DevSecOps Scanner:** Parses GitHub Actions workflows to detect hardcoded high-risk credentials (`AWS_SECRET_ACCESS_KEY`) and dangerous permissions (`permissions: write-all`).

### 2. Correlation & Attack Chain Detection
* **Stateful Campaign Correlation:** Correlates disparate single events into multi-stage attack chains (e.g., *Brute Force -> Local Account Persistence*).
* **Asset-Weighted Risk Scoring:** Dynamic risk matrix that scales threat severity based on target asset criticality (e.g., Domain Controller `1.5x`, Finance DB `2.0x`).
* **Threat Intelligence Caching:** Integrates AbuseIPDB & VirusTotal consensus scoring into a persistent SQLite lookup cache (`ti_cache`) to optimize API latency.

### 3. SOAR & Analyst Interactive Workflows
* **Automated Playbook Generation:** Attach targeted response steps to incidents automatically based on technique classifications ($T1110, T1003.001, T1136.001$).
* **Analyst Action Queue:** One-click containment actions (*Acknowledge*, *Isolate Host*, *Close Case*) backed by append-only database audit logging (`audit_logs`).

### 4. Interactive Visual Dashboard & API Docs
* **SOC Console UI:** Dark-mode responsive dashboard with real-time severity metrics and tabbed navigation.
* **Chart.js Metrics:** Interactive severity distribution donut chart.
* **MITRE ATT&CK Matrix Heatmap:** Dynamic coverage tracker calculating active technique percentage against the reference catalog.
* **OpenAPI / Swagger Specification:** Native API testing sandbox available at `/apidocs`.

---

## 🏗️ Technical Stack

| Component | Technology / Library |
| :--- | :--- |
| **Backend Engine** | Python 3.10+, Flask RESTful API |
| **Database** | SQLite3 (Structured relational storage for logs, incidents, audit, TI cache) |
| **API Documentation** | Flasgger / Swagger OpenAPI 3.0 |
| **UI Framework** | HTML5, CSS3 (IBM Plex Sans/Mono typography), Chart.js |
| **Containerization** | Docker, Docker-Compose |

---

## 📂 Repository Structure

```text
SOC-Triage-Engine/
├── .gitignore                   # Keeps databases and runtime caches out of git tracking
├── Dockerfile                   # Production Docker container blueprint
├── README.md                    # Project documentation & setup guide
├── docker-compose.yml           # One-command container deployment orchestration
├── requirements.txt             # Python dependency manifest
├── soc_engine.py                # Core detection, threat intel, SOAR & Flask engine
├── soc_platform.db              # SQLite relational store (auto-generated)
├── soc_report.html              # Exportable executive HTML report template
├── windows_security_events.json # Sample Windows JSON log stream for testing
└── windows_syslog.log           # Sample raw Windows Syslog stream for testing
🚀 Quickstart GuideOption A: Standard Local RunClone Repository & Navigate to Directory:Bashgit clone [https://github.com/YOUR_GITHUB_USERNAME/SOC-Triage-Engine.git](https://github.com/YOUR_GITHUB_USERNAME/SOC-Triage-Engine.git)
cd SOC-Triage-Engine
Install Dependencies:Bashpip install -r requirements.txt
Launch the Engine:Bashpython soc_engine.py
Access Endpoints:Web Dashboard: http://127.0.0.1:5000Swagger API Documentation: http://127.0.0.1:5000/apidocsOption B: Docker Containerized RunDeploy the entire stack in an isolated container environment with single-command orchestration:Bashdocker-compose up --build
To stop the running container environment:Bashdocker-compose down
📡 REST API ReferenceEndpointMethodDescription/GETRenders the primary SOC Incident Queue & Threat Heatmap Console/ingestPOSTIngests JSON log payloads, triggers detection pipeline, updates incidents/api/incident/actionPOSTExecutes SOAR analyst response (ACKNOWLEDGED, CONTAINED, RESOLVED)/apidocsGETInteractive Swagger OpenAPI 3.0 REST API documentation📊 Sample Ingestion PayloadPaste this sample JSON array directly into the Log Ingestion tab at http://127.0.0.1:5000 to trigger campaign correlation:JSON[
  {
    "event_id": 4625,
    "timestamp": "2026-09-23 02:00:00",
    "user": "Administrator",
    "source_ip": "185.220.101.5",
    "process_name": "C:\\Windows\\System32\\svchost.exe"
  },
  {
    "event_id": 4720,
    "timestamp": "2026-09-23 02:02:10",
    "user": "Administrator",
    "source_ip": "185.220.101.5",
    "target_user": "backdoor_admin"
  },
  {
    "event_id": 10,
    "timestamp": "2026-09-23 02:05:00",
    "user": "SYSTEM",
    "source_ip": "192.168.1.100",
    "process_name": "lsass.exe"
  }
]
🎯 MITRE ATT&CK Matrix MappingThe platform evaluates event logs against the following MITRE ATT&CK technique catalog:T1110 - Brute Force (Credential Access)T1003.001 - OS Credential Dumping: LSASS Memory (Credential Access)T1552.001 - Unsecured Credentials: Credentials In Files (Credential Access)T1136.001 - Create Account: Local Account (Persistence)T1053 - Scheduled Task/Job (Persistence)T1059.001 - Command and Scripting Interpreter: PowerShell (Execution)T1078 - Valid Accounts (Defense Evasion)T1071 - Application Layer Protocol (Command and Control)📜 License & UsageThis project is open-source and available under the MIT License. Built as part of a Cyber Security Engineering portfolio.
