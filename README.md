# PhishTriage

Automated Phishing & Incident Triage Pipeline — a lightweight SOAR-style educational project using Python and Flask.

## Features
- Upload .eml files or paste raw email source
- Extract email headers and URL indicators
- Identify candidate IP addresses in email source
- Calculate Low, Medium, or High preliminary risk scores
- Optional VirusTotal and urlscan.io enrichment
- Generate downloadable JSON incident reports
- Health endpoint at /health

## Requirements
- Python 3.10+
- Flask
- Requests

## Installation on Windows

Open PowerShell in the PhishTriage folder.

Create a virtual environment:

    py -m venv .venv

Activate it:

    .\.venv\Scripts\Activate.ps1

Install dependencies:

    python -m pip install -r requirements.txt

Run the application:

    python app.py

Open this address in your browser:

    http://127.0.0.1:5000

## Optional API configuration

Set your API keys in PowerShell before starting the application:

    $env:VT_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
    $env:URLSCAN_API_KEY="YOUR_URLSCAN_API_KEY"

    python app.py

Obtain keys through the official provider websites. Keep keys private.

## Project workflow

1. Input an email or suspicious URL.
2. Parse the email and extract indicators.
3. Apply explainable heuristic checks.
4. Query configured threat-intelligence services.
5. Calculate a preliminary risk score.
6. Display findings and recommended SOC actions.
7. Download the JSON incident report.

## Important limitations

The risk score is a triage aid, not proof that an email is malicious or safe. Extracted IP addresses are candidates, not necessarily verified sender IPs. API results can be incomplete. This project is intended for local educational use, not production deployment.
