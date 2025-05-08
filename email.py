import email
from email import policy
from email.parser import BytesParser
import re
import requests
import time

# --- Replace this with your actual VirusTotal API Key ---
API_KEY = "3e91ad248c864616cae1edf211e178b9a9cd56a0d98220d65e48bbe53a6a7e88"

def parse_email_header(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "From": msg["From"],
        "To": msg["To"],
        "Subject": msg["Subject"],
        "Return-Path": msg["Return-Path"],
        "Received": msg.get_all("Received"),
        "Authentication-Results": msg["Authentication-Results"]
    }

    return headers

def detect_red_flags(headers):
    flags = []

    from_email = headers["From"] or ""
    return_path = headers["Return-Path"] or ""

    if return_path and return_path not in from_email:
        flags.append("⚠️ 'From' and 'Return-Path' domains do not match")

    if re.search(r"(hotmail|yahoo|gmail)\.com", from_email, re.IGNORECASE):
        flags.append("⚠️ Email is from a public domain provider")

    auth_results = headers.get("Authentication-Results", "")
    if "fail" in (auth_results or "").lower():
        flags.append("❌ Authentication (SPF/DKIM/DMARC) failed")

    return flags

def scan_url_virustotal(url):
    headers = {
        "x-apikey": API_KEY
    }

    print(f"\n🔍 Submitting URL to VirusTotal: {url}")
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        print("❌ Failed to submit URL for scanning")
        return None

    url_id = response.json()["data"]["id"]
    time.sleep(15)

    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{url_id}",
        headers=headers
    ).json()

    stats = result["data"]["attributes"]["stats"]
    print("\n📊 VirusTotal Analysis Summary:")
    print(f"Harmless: {stats['harmless']}")
    print(f"Suspicious: {stats['suspicious']}")
    print(f"Malicious: {stats['malicious']}")

    return stats

def save_report(headers, red_flags, url=None, vt_stats=None, filename="email_report.md"):
    with open(filename, "w") as f:
        f.write("# Email Analysis Report\n\n")
        f.write("## Header Information\n")
        for k, v in headers.items():
            f.write(f"- **{k}**: {v}\n")

        f.write("\n## Red Flags\n")
        if red_flags:
            for flag in red_flags:
                f.write(f"- {flag}\n")
        else:
            f.write("- ✅ No red flags detected\n")

        if url and vt_stats:
            f.write("\n## VirusTotal URL Scan\n")
            f.write(f"- **URL**: {url}\n")
            f.write(f"- Harmless: {vt_stats['harmless']}\n")
            f.write(f"- Suspicious: {vt_stats['suspicious']}\n")
            f.write(f"- Malicious: {vt_stats['malicious']}\n")

    print(f"\n📝 Report saved as: {filename}")

def analyze_email(file_path):
    headers = parse_email_header(file_path)
    red_flags = detect_red_flags(headers)

    print("\n📧 Email Header Information:")
    for key, value in headers.items():
        print(f"{key}: {value}")

    print("\n🚨 Detected Red Flags:")
    if red_flags:
        for flag in red_flags:
            print(flag)
    else:
        print("✅ No immediate red flags detected.")

    url_input = input("\nEnter a URL from the email to check (or press Enter to skip): ")
    vt_stats = None
    if url_input:
        vt_stats = scan_url_virustotal(url_input)

    save_report(headers, red_flags, url_input if url_input else None, vt_stats)

if __name__ == "__main__":
    print("📥 Email Phishing Detection & Analysis Tool")
    path = input("Enter the path to the .eml email file: ")
    analyze_email(path)
