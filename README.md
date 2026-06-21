# ioc-aggregator
Threat Intelligence Platform
An end-to-end, high-performance threat intelligence and Indicators of Compromise (IOC) aggregation dashboard. This platform aggregates, classifies, and visualizes cyber threat intelligence (IPs, Domains, URLs, UPI handles) using a combination of heuristic scoring, safe-list exceptions, and user-submitted reports.

Featuring a stunning cybernetic glassmorphic UI, the application operates in dual-mode: it runs seamlessly via a Node.js/Express backend API or runs fully client-side using an offline heuristic engine (localStorage fallback) if the server is unreachable.

✨ Features
Unified Search & Auto-Detection: Search for threat indicators using tabs or let the auto-classifier detect the input type:
Domains (heuristics flag suspicious TLDs, keyword matches like secure-login, etc.)
IP Addresses (flags malicious hostings, botnet-related open ports)
URLs (detects redirect patterns, insecure HTTP schemes, phishing keywords)
UPI IDs (checks for fraudulent transaction addresses, payment impersonation)
Heuristic Analysis Engine: Leverages risk-based scoring (
0
0 to 
100
100) to evaluate and categorize threat indicators in real-time.
Dynamic Threat Ingestion Feed: Simulates a live feed by generating mock threat items in memory (every 30 seconds on the backend) alongside persistent local threat database records.
User Submission Portal: Allows security analysts and users to submit new threat indicators, which are saved immediately and aggregated into the active database.
Interactive Analytics Dashboard: Beautiful charting powered by Chart.js displaying:
Live severity distribution (Safe, Suspicious, Malicious)
Threat indicator type breakdown
Category threat profiles
Dual Execution Modes:
API Mode: Leverages Node.js, Express, and a JSON-based file storage (db.json) for persistence and mock seed generation.
Local/Offline Fallback: Automatic transition to fully client-side evaluation using the HTML5 local storage API when the backend is offline.
🏗️ Project Structure
text

ioc-aggregator/
├── public/                 # Frontend Static Directory
│   ├── index.html          # Core dashboard HTML structure (Outfit & Jakarta Sans fonts, widgets)
│   ├── app.js              # Frontend UI logic, state management, LocalEngine fallback
│   └── styles.css          # Glassmorphic CSS design system, cybernetic grid, neon animations
├── db.json                 # JSON file database storing persistent indicators & feeds
├── server.js               # Node.js + Express backend, API endpoints, mock generator
├── index.html              # Root redirect file mapping to public/index.html
├── package.json            # Node.js project manifest & dependencies
└── README.md               # Documentation (This file)
⚡ Tech Stack
Frontend: Vanilla HTML5, Vanilla CSS3 (Custom Variables, Flexbox/Grid, Keyframe Animations), Vanilla JavaScript (ES6+).
Visualization: Chart.js (interactive donut, radar, and bar charts).
Backend: Node.js, Express.js.
Database: File-based JSON Database (db.json).
🚀 Getting Started
📋 Prerequisites
Ensure you have Node.js installed (version 16+ recommended).

1. Installation
Navigate to the project root directory and install dependencies:

bash

npm install
2. Start the Backend API Server
Launch the Express backend server on default port 3000:

bash

npm start
You should see:

text

IOC Aggregator backend server running at http://localhost:3000
3. Open the Dashboard
Open your web browser and navigate to:

text

http://localhost:3000
Note: If you run the project without starting the server, you can simply double-click public/index.html to run in Local Offline Engine mode.

🔌 API Documentation
All API endpoints are hosted relative to the server (e.g., http://localhost:3000/api).

1. GET /api/feed
Retrieves the latest 30 aggregated threat feed indicators, combining live dynamic threats with database seeds.

Response: Array of threat indicator objects.
2. GET /api/stats
Calculates database-wide analytics, including severity counts, category distribution, and IOC type counts.

Response: JSON payload with system telemetry and metrics.
3. POST /api/check
Performs classification and heuristic analysis on a query.

Payload:
json

{
  "query": "fraudulent-bank-verify.com",
  "type": "auto"
}
Response: Rich threat telemetry, details object (hosting, registrar, age), threat status, and final risk score.
4. POST /api/submit
Submits a new threat indicator to the database.

Payload:
json

{
  "type": "upi",
  "value": "fake-refund-support@oksbi",
  "category": "Impersonation UPI Fraud",
  "comments": "User reported getting a lottery SMS asking to pay fees via this UPI ID."
}
Response: 201 Created along with the registered database entry.
⚙️ Threat Scoring Heuristics
The evaluation engine calculates threat scores using dynamic parameters:

Risk Score
=
Baseline Risk
+
∑
Δ
Risk Factors
Risk Score=Baseline Risk+∑ΔRisk Factors
Where:

Baseline Risk: Initial starting risk score (typically 15).
Scam Keywords: Presence of phishing/scam terms (e.g., login, bank, kyc, refund, verify) adds 
+
55
+55 to 
+
60
+60 to the risk score.
Suspicious TLDs: Web domains ending in .xyz, .top, .cc, or .info add 
+
20
+20.
Length Penalty: Excessively long domain names add 
+
10
+10.
Protocol Vulnerability: Use of insecure HTTP protocols on URL indicators adds 
+
25
+25.
Safe-list Bypass: Known trusted items (like google.com or 8.8.8.8) bypass the heuristics and are immediately given a risk score of 
2
2 (Safe).
