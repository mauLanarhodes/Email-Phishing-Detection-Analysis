# Email Phishing Detection & Analysis Tool

## Overview

This project is a Python-based tool designed to automatically detect suspicious email characteristics and scan embedded links for potential phishing threats. It parses `.eml` email files, extracts metadata and body content, identifies red flags (such as header mismatches), and automatically scans embedded URLs using the VirusTotal API.

The tool is lightweight, extensible, and designed with real-world security workflows in mind. It simulates part of what a security analyst might do during triage, making it a valuable learning project in email security, threat intelligence, and digital forensics.

---

## Key Features

- **Email Header Analysis**
  - Parses `.eml` files using Python’s built-in `email` library
  - Detects mismatches between `From` and `Return-Path`
  - Verifies authentication results (SPF, DKIM, DMARC)

- **Body & Link Inspection**
  - Extracts links from both plain text and HTML parts
  - Supports detection of embedded hyperlinks using BeautifulSoup
  - Scans URLs using the [VirusTotal API](https://www.virustotal.com/)

- **Automated Report Generation**
  - Generates Markdown reports summarizing header data, red flags, and scan results
  - Easily sharable for audit or documentation

- **Zero User Input**
  - Automatically finds and evaluates the first URL without user intervention

---

## Why I Built This

This project simulates tasks often performed by Security Analysts or SOC teams when reviewing suspicious emails. It reflects key cybersecurity concepts such as:

- Threat detection and triage
- Email header forensics
- Open-source intelligence (OSINT) integration
- Script automation and report generation

I built this to sharpen my skills in cybersecurity tooling and demonstrate my ability to design and implement practical security solutions.

---

## Technologies Used

- **Python 3**
- `email` and `re` (built-in)
- `requests` (HTTP client)
- `bs4` (BeautifulSoup for HTML parsing)
- VirusTotal API (free tier)

---

## Getting Started

**### 1. Clone the repository**
```bash
git clone https://github.com/yourusername/phishing-email-detector.git
cd phishing-email-detector

### 2. Set up a virtual environment
bash
Copy
Edit
python -m venv .venv
.venv\Scripts\activate   # On Windows

### 3. Install dependencies
bash
Copy
Edit
pip install -r requirements.txt


**### 4. Replace your VirusTotal API key
**Open email_analyzer.py and replace:

python
Copy
Edit
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

**### 5. Run the program**
bash
Copy
Edit
python email_analyzer.py
Provide the path to your .eml file when prompted.

Example Output
rust
Copy
Edit
Email Header Information:
From: support@example.com
Return-Path: alerts@fake.com
Authentication: SPF fail

Detected Red Flags:
- 'From' and 'Return-Path' domains do not match
- SPF failed

Found URL: http://malicious-phish.xyz
VirusTotal Result: Malicious

Report saved as: email_report.md
