
import os
import json
from collections import defaultdict
import zipfile
import csv
import requests

def main():
    # STEP 1: Load local advisories
    advisories = load_local_advisories("advisory-database/advisories/github-reviewed")
    print(f"✅ Loaded {len(advisories)} advisories.")
    

    # STEP 2: Classify by severity
    classified = classify_by_severity(advisories)
    for severity, items in classified.items():
        print(f"📦 {severity.upper()}: {len(items)} advisories")

    # STEP 3: Write advisories to individual files
    write_advisories_to_files(classified, output_dir="advisories")
    print("📝 Advisory files written to /advisories/<severity>/")
    
    # Create ZIP archives for each severity category
    zip_advisory_folders(input_dir="advisories", output_dir="zips")
    
    ''' THIS ENTIRE section if for the NO KEV option
    # STEP 4: Optionally load KEV CVE list (can be empty for now)
    #kev_set = set()  # You can fill this later via a KEV fetch function
    # STEP 5: Generate CSV report
    write_csv(classified, kev_set, output_file="advisories.csv")
    print("📄 advisories.csv generated.")
    '''

    # STEP 4a: Fetch KEV CVE set
    kev_set = fetch_kev_cves()
    
    # STEP 5: Generate CSV report with KEV flag
    write_csv(classified, kev_set, output_file="advisories_kev.csv")
    print("📄 advisories.csv generated with KEV flag.")


def load_local_advisories(base_path="advisory-database/advisories/github-reviewed"):
    advisories = []

    for root, _, files in os.walk(base_path):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    try:
                        advisory = json.load(f)
                        advisories.append(advisory)
                    except json.JSONDecodeError:
                        print(f"❌ Failed to parse: {file_path}")
    
    return advisories


def classify_by_severity(advisories):
    classified = defaultdict(list)
    for adv in advisories:
        severity = adv.get("database_specific", {}).get("severity", "UNKNOWN").lower()
        classified[severity].append(adv)
    return classified

def write_advisories_to_files(classified, output_dir="advisories"):
    os.makedirs(output_dir, exist_ok=True)
    for severity, items in classified.items():
        severity_dir = os.path.join(output_dir, severity)
        os.makedirs(severity_dir, exist_ok=True)
        for advisory in items:
            filename = f"{advisory['id']}.json"
            with open(os.path.join(severity_dir, filename), "w") as f:
                json.dump(advisory, f, indent=2)



def zip_advisory_folders(input_dir="advisories", output_dir="zips"):
    os.makedirs(output_dir, exist_ok=True)
    
    # Iterate over each severity folder (low, moderate, high, critical)
    for severity in os.listdir(input_dir):
        severity_path = os.path.join(input_dir, severity)
        
        if not os.path.isdir(severity_path):
            continue  # Skip if it's not a directory
        
        zip_filename = os.path.join(output_dir, f"{severity}.zip")
        
        # Create a zip file for each severity folder
        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the severity folder
            for root, _, files in os.walk(severity_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, input_dir)  # Preserve relative path
                    zipf.write(file_path, arcname)
                    
        print(f"✅ Created: {zip_filename}")

def fetch_kev_cves():
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    try:
        response = requests.get(kev_url)
        response.raise_for_status()
        kev_data = response.json()

        kev_cves = {
            item["cveID"]
            for item in kev_data.get("vulnerabilities", [])
            if "cveID" in item
        }

        print(f"🛡️ Loaded {len(kev_cves)} CVEs from KEV catalog.")
        return kev_cves

    except Exception as e:
        print(f"⚠️ Failed to fetch KEV data: {e}")
        return set()


def write_csv(classified, kev_set, output_file="advisories.csv"):
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["GHSA ID", "CVE ID", "Severity", "Package", "Ecosystem", "Summary", "KEV"])

        for severity, advisories in classified.items():
            for adv in advisories:
                ghsa_id = adv.get("id", "")
                
                aliases = adv.get("aliases", [])
                cve_id = aliases[0] if aliases else ""

                summary = adv.get("summary", "")
                package = ""
                ecosystem = ""

                if adv.get("affected"):
                    pkg = adv["affected"][0].get("package", {})
                    package = pkg.get("name", "")
                    ecosystem = pkg.get("ecosystem", "")
                
                kev = "1" if cve_id in kev_set else ""
                writer.writerow([ghsa_id, cve_id, severity.upper(), package, ecosystem, summary, kev])


if __name__ == "__main__":
    main()

