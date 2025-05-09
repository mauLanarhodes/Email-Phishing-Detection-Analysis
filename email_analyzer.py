import email
import bs4
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import re
import requests
import time

API_KEY = ""  # Replace with your actual API key

def get_email_body(msg):
    text_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" not in content_disposition:
                payload = part.get_payload(decode=True)
                if payload:
                    decoded = payload.decode(errors='ignore')
                    if content_type == "text/plain":
                        text_body += decoded
                    elif content_type == "text/html":
                        html_body += decoded
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            text_body = payload.decode(errors='ignore')

    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        links = [a['href'] for a in soup.find_all('a', href=True)]
        return text_body + "\n" + "\n".join(links)
    
    return text_body

def parse_email_header(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "From": msg["From"],
        "To": msg["To"],
        "Subject": msg["Subject"],
        "Return-Path": msg["Return-Path"],
        "Received": msg.get_all("Received"),
        "Authentication-Results": msg["Authentication-Results"],
        "Body": get_email_body(msg)
    }

    return headers

def detect_red_flags(headers):
    flags = []

    from_email = headers["From"] or ""
    return_path = headers["Return-Path"] or ""

    if return_path and return_path not in from_email:
        flags.append("'From' and 'Return-Path' domains do not match")

    if re.search(r"(hotmail|yahoo|gmail)\.com", from_email, re.IGNORECASE):
        flags.append("Email is from a public domain provider")

    auth_results = headers.get("Authentication-Results", "")
    if "fail" in (auth_results or "").lower():
        flags.append("Authentication (SPF/DKIM/DMARC) failed")

    return flags

def scan_url_virustotal(url):
    headers = {
        "x-apikey": API_KEY
    }

    print(f"\nSubmitting URL to VirusTotal: {url}")
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        print("Failed to submit URL for scanning")
        return None

    url_id = response.json()["data"]["id"]
    time.sleep(15)

    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{url_id}",
        headers=headers
    ).json()

    stats = result["data"]["attributes"]["stats"]
    print("\nVirusTotal Analysis Summary:")
    print(f"Harmless: {stats['harmless']}")
    print(f"Suspicious: {stats['suspicious']}")
    print(f"Malicious: {stats['malicious']}")

    return stats

def save_report(headers, red_flags, url=None, vt_stats=None, filename="email_report.md"):
    with open(filename, "w") as f:
        f.write("# Email Analysis Report\n\n")
        f.write("## Header Information\n")
        for k, v in headers.items():
            if k != "Body":
                f.write(f"- **{k}**: {v}\n")

        f.write("\n## Red Flags\n")
        if red_flags:
            for flag in red_flags:
                f.write(f"- {flag}\n")
        else:
            f.write("- No red flags detected\n")

        if url and vt_stats:
            f.write("\n## VirusTotal URL Scan\n")
            f.write(f"- URL: {url}\n")
            f.write(f"- Harmless: {vt_stats['harmless']}\n")
            f.write(f"- Suspicious: {vt_stats['suspicious']}\n")
            f.write(f"- Malicious: {vt_stats['malicious']}\n")

    print(f"\nReport saved as: {filename}")

def analyze_email(file_path):
    headers = parse_email_header(file_path)
    red_flags = detect_red_flags(headers)

    print("\nEmail Header Information:")
    for key, value in headers.items():
        if key != "Body":
            print(f"{key}: {value}")

    print("\nDetected Red Flags:")
    if red_flags:
        for flag in red_flags:
            print(flag)
    else:
        print("No immediate red flags detected.")

    body = headers.get("Body", "")
    found_urls = re.findall(r'https?://[^\s"<>\]]+', body)
    vt_stats = None

    if found_urls:
        print(f"\nFound URL: {found_urls[0]}")
        vt_stats = scan_url_virustotal(found_urls[0])
    else:
        print("\nNo URLs found in email body.")

    save_report(headers, red_flags, found_urls[0] if found_urls else None, vt_stats)

if __name__ == "__main__":
    print("Email Phishing Detection & Analysis Tool")
    path = input("Enter the path to the .eml email file: ").strip().strip('"')
    analyze_email(path)
