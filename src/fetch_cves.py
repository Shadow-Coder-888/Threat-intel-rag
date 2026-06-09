import requests
import json
import time
from pathlib import Path
from tqdm import tqdm

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RESULTS_PER_PAGE = 100
MAX_PAGES = 5


def fetch_cve_page(start_index: int) -> dict:
    params = {
        "resultsPerPage": RESULTS_PER_PAGE,
        "startIndex": start_index,
    }

    response = requests.get(
        NVD_BASE_URL,
        params=params,
        timeout=30,
    )

    response.raise_for_status()
    return response.json()


def extract_cve_data(raw_cve: dict) -> dict:
    cve_id = raw_cve.get("id", "")

    descriptions = raw_cve.get("descriptions", [])
    description = ""

    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    severity = "UNKNOWN"
    score = 0.0

    metrics = raw_cve.get("metrics", {})

    if "cvssMetricV31" in metrics:
        cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        score = cvss_data.get("baseScore", 0.0)

    elif "cvssMetricV30" in metrics:
        cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        score = cvss_data.get("baseScore", 0.0)

    elif "cvssMetricV2" in metrics:
        metric = metrics["cvssMetricV2"][0]
        cvss_data = metric.get("cvssData", {})
        severity = metric.get("baseSeverity", "UNKNOWN")
        score = cvss_data.get("baseScore", 0.0)

    published = raw_cve.get("published", "")[:10]

    return {
        "id": cve_id,
        "description": description,
        "severity": severity,
        "score": score,
        "published": published,
    }


def fetch_all_cves():
    all_cves = []

    print(
        f"Fetching up to {MAX_PAGES * RESULTS_PER_PAGE} CVEs from NVD API..."
    )

    for page in tqdm(range(MAX_PAGES), desc="Pages"):
        start_index = page * RESULTS_PER_PAGE

        try:
            raw_data = fetch_cve_page(start_index)
            vulnerabilities = raw_data.get("vulnerabilities", [])

            for vuln in vulnerabilities:
                cve_data = extract_cve_data(vuln["cve"])

                if cve_data["description"]:
                    all_cves.append(cve_data)

            # NVD rate-limit protection
            time.sleep(1)

        except requests.exceptions.RequestException as e:
            print(f"Error on page {page}: {e}")
            continue
        except KeyError as e:
            print(f"Missing expected key on page {page}: {e}")
            continue

    output_path = Path("data/cves.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(all_cves, f, indent=2, ensure_ascii=False)

    print(f"\nDone! {len(all_cves)} CVEs saved to {output_path}")

    return all_cves


if __name__ == "__main__":
    fetch_all_cves()