# 🛡️ ThreatSight — Cloud-Native SOC Dashboard

A full-stack, cloud-hosted **SOC-style security platform** that ingests telemetry (honeypot events, Nessus findings, and Wireshark/PCAP-derived logs), enriches it with AI-assisted analysis, and visualizes results in a modern dashboard.

---

## Architecture

```text
[ Data Sources ]
  • OpenCanary (honeypot logs)
  • Nessus reports (PDF / exports)
  • Wireshark / PCAP-derived telemetry
        ↓
[ Backend API (Node / Express) ]
  • Upload + parsing
  • Normalization + transforms
  • AI enrichment (Gemini)
        ↓
[ MongoDB ]
  • reports
  • vulnhoneypots
  • vulnnessus
  • vulnwiresharks
        ↓
[ Frontend (React + Tailwind + ECharts) ]
  • SOC dashboards
  • tables + report views
  • severity + filtering
```
### General Respository Layout
```text
.
├── backend/
│   ├── src/
│   │   ├── app.js
│   │   ├── server.js
│   │   ├── config/               # DB + env configuration
│   │   ├── controllers/          # report + analysis controllers
│   │   ├── routes/               # API routes
│   │   ├── middleware/           # uploads + error handling
│   │   ├── models/               # MongoDB schemas
│   │   ├── services/             # AI, transforms, PDFs
│   │   └── utils/                # logging + validation
│   ├── backend_standAlone/
│   │   ├── Orchestra/            # pcap → json + test scripts
│   │   └── strip_json.py
│   ├── temp/
│   │   ├── uploads/
│   │   └── outputs/
│   └── testScripts/
│       └── testNessus.js
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── pages/
│   │   └── store/
│   └── public/
└── reports/                      # (optional) sample reports
```

## Data Model (MongoDB)
### reports table
#### Example
```text
{
  reportName: "Nessus Scan - Test Import",
  generatedAt: null,
  mode: "Nessus",
  uploadedAt: "2026-02-21T23:45:10.374Z",
  createdAt: "2026-02-21T23:45:10.378Z",
  updatedAt: "2026-02-21T23:45:10.378Z"
}
```
### vulnhoneypots table
#### Example
```text
{
  event_id: "72eac5f6647ab35724447ca10f3f5914b1aabde4",
  attack_type: "ssh_login_attempt",
  src_ip: "192.168.56.128",
  src_port: 38160,
  dst_ip: "192.168.56.130",
  dst_port: 22,
  logtype: 4000,
  timestamp: "2026-02-22 05:20:34.281979"
}
```
### vulnnessus table
#### Example
```text
{
  pluginId: "134862",
  reportId: "<ObjectId: reports._id>",
  host: "192.168.56.129",
  name: "Apache Tomcat AJP Connector Request Injection (Ghostcat)",
  severity: "CRITICAL",
  cvssV3: 9.8,
  epss: 0.9447,
  vpr: 8.9,
  createdAt: "2026-02-21T23:45:10.599Z",
  updatedAt: "2026-02-21T23:45:10.599Z"
}
```
### vulnwiresharks table
#### Example
```text
{
  _id: "Report_2026-02-22_024721_N1",
  reportId: "Report_2026-02-22_024721",
  timestamp: "2026-02-22T07:47:23.689Z",
  SrcIP: "192.168.56.128",
  DestIP: "192.168.56.2",
  Protocol: "DNS",
  Info: "Standard query PTR 130.56.168.192.in-addr.arpa"
}
```

## Getting Started
### Prequisites
* Node.js 18+
* npm
* MongoDB (local or Atlas)
* (Optional) Python 3.9+ for PCAP tooling
### Setup
1) Clone the repository
```text
git clone <your-repo-url>
cd <your-repo>
```
2) Configure environment variables
#### Create backend/.env:
```text
PORT=5000
MONGO_URI=mongodb://localhost:27017/threatsight
GEMINI_API_KEY=your-gemini-api-key
CORS_ORIGIN=http://localhost:5173
```
### Run Locally
1) Start the backend
```text
cd backend
npm install
npm run dev
```
#### Backend runs at: 
```text
http://localhost:3001
```
2) Start the frontend
```text
cd frontend
npm install
npm run dev
```
#### Open:
```text
http://localhost:5173
```

## Important Pipelines

## Built With
* Frontend: React, Tailwind CSS, Apache ECharts, Vite, JavaScript
* Backend: Node.js, Express.js, JavaScript
* Database: MongoDB, Mongoose
* Security: Wireshark, OpenCanary, Nessus, Honeypot
* AI: Google Gemini
* Platform: Linux, Docker (optional), Bash, VS Code, Github

## Future Improvements
* Alerting & notifications
* Live updating data for wireshark
* More advanced UI
* More autonomous system
* Long-term retention policies

## Disclaimer
This project is intended for educational use only.
Do not deploy honeypots or monitor networks you do not own or have explicit permission to test.
