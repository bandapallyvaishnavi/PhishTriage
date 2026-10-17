import os
import re
import json
import ipaddress
import base64
from io import BytesIO
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

import requests
from flask import (
    Flask, render_template, request, jsonify,
    send_file, flash
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "local-demo-change-this-key"
)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+',
    re.IGNORECASE
)
IP_PATTERN = re.compile(
    r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
)


def unique(items):
    result = []
    seen = set()

    for item in items:
        item = item.rstrip(".,;:)")
        if item and item not in seen:
            seen.add(item)
            result.append(item)

    return result


def extract_urls(text):
    return unique(URL_PATTERN.findall(text or ""))



def parse_email(raw_bytes):
    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_bytes)

    header_names = [
        "From", "To", "Subject", "Date",
        "Reply-To", "Return-Path", "Message-ID"
    ]

    headers = {
        name: str(message.get(name, ""))
        for name in header_names
    }

    body_parts = []

    if message.is_multipart():
        for part in message.walk():
            if (
                part.get_content_type() == "text/plain"
                and not part.get_content_disposition()
            ):
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            body_parts.append(message.get_content())
        except Exception:
            pass

    body = "\n".join(body_parts)

    # Extract candidate IPv4 addresses from email routing headers.
    # Do not scan the message body for IP addresses and mistake
    # them for sender IPs.
    sender_ips = []
    received_headers = message.get_all("Received", [])

    for received_header in received_headers:
        candidates = IP_PATTERN.findall(str(received_header))

        for candidate in candidates:
            try:
                ip = ipaddress.ip_address(candidate)

                # Keep only publicly routable addresses.
                if ip.version == 4 and ip.is_global:
                    sender_ips.append(str(ip))
            except ValueError:
                continue

    sender_ips = unique(sender_ips)

    raw_source = raw_bytes.decode(
        "utf-8", errors="replace"
    )

    urls = extract_urls(body + "\n" + raw_source)

    return {
        "headers": headers,
        "body": body,
        "sender_ips": sender_ips,
        "urls": urls
    }


def virustotal_lookup(url):
    api_key = os.environ.get("VT_API_KEY", "").strip()

    if not api_key:
        return {
            "status": "not_configured",
            "message": "VirusTotal API key not configured."
        }

    try:
        encoded = base64.urlsafe_b64encode(
            url.encode("utf-8")
        ).decode("ascii").strip("=")

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded}",
            headers={"x-apikey": api_key},
            timeout=10
        )

        if response.status_code == 404:
            return {
                "status": "not_found",
                "message": "URL not found in VirusTotal."
            }

        response.raise_for_status()
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        return {
            "status": "ok",
            "malicious": malicious,
            "suspicious": suspicious,
            "message": (
                f"{malicious} malicious and "
                f"{suspicious} suspicious detections."
            )
        }

    except requests.RequestException as exc:
        code = getattr(getattr(exc, "response", None), "status_code", None)
        message = "VirusTotal request failed."
        if code:
            message = f"VirusTotal request failed (HTTP {code})."
        return {"status": "error", "message": message}
    except (KeyError, TypeError, ValueError):
        return {
            "status": "error",
            "message": "Unexpected VirusTotal response."
        }


def urlscan_lookup(url):
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()

    if not api_key:
        return {
            "status": "not_configured",
            "message": "urlscan.io API key not configured."
        }

    try:
        host = urlparse(url).hostname

        if not host:
            return {
                "status": "error",
                "message": "Could not extract URL hostname."
            }

        response = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.domain:{host}", "size": 1},
            headers={"API-Key": api_key},
            timeout=15
        )
        response.raise_for_status()
        results = response.json().get("results", [])

        if not results:
            return {
                "status": "not_found",
                "message": "No matching scan found."
            }

        item = results[0]
        return {
            "status": "ok",
            "message": "Existing scan found.",
            "result_url": item.get("result", ""),
            "verdict": item.get("verdicts", {}).get("overall", {})
        }

    except requests.RequestException as exc:
        code = getattr(getattr(exc, "response", None), "status_code", None)
        message = "urlscan.io request failed."
        if code:
            message = f"urlscan.io request failed (HTTP {code})."
        return {"status": "error", "message": message}


def triage(email_data, pasted_url=""):
    headers = email_data.get("headers", {})

    urls = unique(
        email_data.get("urls", [])
        + ([pasted_url] if pasted_url else [])
    )

    score = 0
    findings = []

    sender = headers.get("From", "").strip().lower()
    reply_to = headers.get("Reply-To", "").strip().lower()

    if sender and reply_to and sender != reply_to:
        score += 15
        findings.append(
            "Reply-To differs from From; verify the sender."
        )

    if not sender:
        score += 5
        findings.append("Sender information is missing.")

    if not headers.get("Subject"):
        score += 3
        findings.append("Email subject is missing.")

    if len(urls) >= 3:
        score += 10
        findings.append(
            f"The message contains {len(urls)} URLs."
        )

    for url in urls:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if parsed.scheme != "https":
            score += 8
            findings.append(
                f"Non-HTTPS URL: {url}"
            )

        if hostname.startswith("xn--") or ".xn--" in hostname:
            score += 15
            findings.append(
                f"Punycode hostname requires review: {hostname}"
            )

        if re.search(
            r'login|verify|password|urgent|wallet|bank|secure-update',
            url,
            re.IGNORECASE
        ):
            score += 8
            findings.append(
                f"Potentially sensitive lure keyword in URL: {url}"
            )

        if "@" in parsed.netloc:
            score += 12
            findings.append(
                f"URL contains user-info before the hostname: {url}"
            )

    enrichments = []

    # Limit external lookups to the first five URLs.
    for url in urls[:5]:
        vt = virustotal_lookup(url)
        scan = urlscan_lookup(url)

        if vt.get("status") == "ok":
            score += min(
                40,
                vt.get("malicious", 0) * 10
                + vt.get("suspicious", 0) * 4
            )

            if vt.get("malicious", 0) > 0:
                findings.append(
                    f"VirusTotal reports malicious detections for {url}."
                )

        enrichments.append({
            "url": url,
            "virustotal": vt,
            "urlscan": scan
        })

    score = min(score, 100)

    if score >= 50:
        level = "High"
        actions = [
            "Escalate for high-priority analyst review.",
            "Preserve the original email and headers.",
            "Check whether recipients clicked links.",
            "Validate indicators before blocking them."
        ]
    elif score >= 20:
        level = "Medium"
        actions = [
            "Review sender legitimacy and all extracted URLs.",
            "Correlate with mail gateway logs.",
            "Escalate if additional suspicious evidence appears."
        ]
    else:
        level = "Low"
        actions = [
            "Verify the sender and business context.",
            "Treat the message as unverified, not automatically safe.",
            "Escalate if new evidence appears."
        ]

    if not findings:
        findings.append(
            "No configured heuristic indicators were triggered. "
            "This does not prove the message is safe."
        )

    return {
        "score": score,
        "level": level,
        "findings": unique(findings),
        "recommended_actions": actions,
        "enrichments": enrichments,
        "generated_at": datetime.now(
            timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")
    }, urls


@app.route("/", methods=["GET", "POST"])
def index():
    parsed = {
        "headers": {},
        "sender_ips": [],
        "urls": [],
        "body": ""
    }
    result = None
    report_json = ""

    if request.method == "POST":
        pasted_url = request.form.get(
            "suspicious_url", ""
        ).strip()

        raw_email = request.form.get(
            "raw_email", ""
        ).strip()

        upload = request.files.get("email_file")

        try:
            if upload and upload.filename:
                filename = secure_filename(upload.filename)

                if not filename.lower().endswith(".eml"):
                    flash("Please upload an .eml file.")
                    return render_template(
                        "index.html",
                        parsed=parsed,
                        result=None
                    )

                parsed = parse_email(upload.read())

            elif raw_email:
                parsed = parse_email(
                    raw_email.encode("utf-8")
                )

            elif not pasted_url:
                flash(
                    "Upload an .eml file, paste an email, "
                    "or enter a URL."
                )
                return render_template(
                    "index.html",
                    parsed=parsed,
                    result=None
                )

            result, urls = triage(parsed, pasted_url)
            parsed["urls"] = urls

            report_json = json.dumps(
                {"parsed": parsed, "result": result},
                indent=2,
                ensure_ascii=False
            )

        except Exception:
            flash(
                "Could not parse this input. "
                "Check that the email source is valid."
            )

    return render_template(
        "index.html",
        parsed=parsed,
        result=result,
        report_json=report_json
    )


@app.post("/download-report")
def download_report():
    try:
        report = json.loads(
            request.form.get("report_json", "{}")
        )
    except json.JSONDecodeError:
        return "Invalid report", 400

    content = json.dumps(
        report, indent=2, ensure_ascii=False
    ).encode("utf-8")

    return send_file(
        BytesIO(content),
        mimetype="application/json",
        as_attachment=True,
        download_name="phishtriage-incident-report.json"
    )


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "PhishTriage"
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )