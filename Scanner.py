import requests
import time

NVD_API_KEY = ""  # Replace with your key if you have one
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

def search_cves(product, version):
    query = f"{product} {version}"
    params = {
        "keywordSearch": query,
        "resultsPerPage": 10
    }
    try:
        response = requests.get(NVD_API_URL, params=params, headers=HEADERS, timeout=15)
        if response.status_code == 200:
            return response.json()
        else:
            print(f"[!] API Error: {response.status_code} – {response.text}")
            return {}
    except requests.RequestException as e:
        print(f"[!] Request error: {e}")
        return {}

def parse_cve_results(data):
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        cve_id = cve["id"]
        desc = cve["descriptions"][0]["value"]

        severity = "UNKNOWN"  # Default
        metrics = cve.get("metrics", {})

        # Prefer CVSS v3.1 if available
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV30" in metrics:
            severity = metrics["cvssMetricV30"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV2" in metrics:
            cvss_v2 = metrics["cvssMetricV2"][0]
            severity = cvss_v2.get("baseSeverity") or cvss_v2["cvssData"].get("baseScore", "UNKNOWN")

        results.append((cve_id, severity, desc))
    return results


def main():
    print("=== CVE Scanner ===")
    product = input("Enter software/product name: ").strip()
    version = input("Enter version number: ").strip()

    print(f"\n🔍 Scanning: {product} {version}")
    data = search_cves(product, version)
    cves = parse_cve_results(data)

    if cves:
        for cve_id, severity, desc in cves:
            print(f"\n {cve_id} | Severity: {severity}")
            print(f"→ {desc[:200]}...")  # Show first 200 chars for readability
    else:
        print("\n✅ No known CVEs found for this software and version.")

    time.sleep(1.5)

if __name__ == "__main__":
    main()


# products - windows 10, ubuntu 20.04, docker 20.10, MySQL 8.0.31, OpenSSH 8.4, nginx 1.18.0