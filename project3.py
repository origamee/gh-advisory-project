
import os
import json
from collections import defaultdict
import zipfile
import csv
import requests

''' SKELETON
def main():
    #load advisories
    
    #classify by severity
    
    #write advisories to 4 folders, by severity i.e. 
    # CRITICAL, HIGH, MODERATE, LOW
    
    #fetch KEV info
    
    #generate CSV report with KEV flag
    
def load_advisories(base_path=""):
     ...
     return advisories
 
 
def classify_by_severity(advisories):
    ...
    return classified

def zip_four_folders(input_dir="", output_dir=""):
    ...
    
def fetch_kev_cves():
    return kev_cves

def write_csv(classified, kev_cves, output_file="advisories.csv"):
    
    
    

if __name__ == "__main__":
    main()

'''
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
    #print(type(advisories))
    #print(len(advisories))
    return advisories


def classify_by_severity(advisories):
    #print(advisories[0])
    '''
    This is what one advisory looks like
    {'schema_version': '1.4.0', 'id': 'GHSA-2c7w-v459-cwgf', 'modified': '2024-11-22T20:20:55Z', 'published': '2022-03-25T00:00:33Z', 'aliases': ['CVE-2022-25568'], 'summary': 'MotionEye allows attackers to access sensitive information', 'details': 'MotionEye v0.42.1 and below allows attackers to access sensitive information via a GET request to /config/list. To exploit this vulnerability, a regular user password must be unconfigured.', 'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}], 'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'motioneye'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '0.43.1b1'}]}]}], 'references': [{'type': 'ADVISORY', 'url': 'https://nvd.nist.gov/vuln/detail/CVE-2022-25568'}, {'type': 'WEB', 'url': 'https://github.com/ccrisan/motioneye/issues/2292'}, {'type': 'WEB', 'url': 'https://github.com/motioneye-project/motioneye/commit/c60b64af5bb8c09189071522a1f6796cb44340b0'}, {'type': 'PACKAGE', 'url': 'https://github.com/motioneye-project/motioneye'}, {'type': 'WEB', 'url': 'https://github.com/pypa/advisory-database/tree/main/vulns/motioneye/PYSEC-2022-43141.yaml'}, {'type': 'WEB', 'url': 'https://www.pizzapower.me/2022/02/17/motioneye-config-info-disclosure'}], 'database_specific': {'cwe_ids': ['CWE-200'], 'severity': 'HIGH', 'github_reviewed': True, 'github_reviewed_at': '2024-11-22T20:20:55Z', 'nvd_published_at': '2022-03-24T17:15:00Z'}}
    '''
    classified = defaultdict(list)
    for adv in advisories:
        severity = adv.get("database_specific", {}).get("severity", "UNKNOWN").lower()
        classified[severity].append(adv)
    '''
    This is what the new classified defaultdict looks like after 
    making the extracted normalized severity a new - first key
    
    defaultdict(<class 'list'>, {'high': [{'schema_version': '1.4.0', 'id': 'GHSA-2c7w-v459-cwgf', 'modified': '2024-11-22T20:20:55Z', 'published': '2022-03-25T00:00:33Z', 'aliases': ['CVE-2022-25568'], 'summary': 'MotionEye allows attackers to access sensitive information', 'details': 'MotionEye v0.42.1 and below allows attackers to access sensitive information via a GET request to /config/list. To exploit this vulnerability, a regular user password must be unconfigured.', 'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'}], 'affected': [{'package': {'ecosystem': 'PyPI', 'name': 'motioneye'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': '0.43.1b1'}]}]}], 'references': [{'type': 'ADVISORY', 'url': 'https://nvd.nist.gov/vuln/detail/CVE-2022-25568'}, {'type': 'WEB', 'url': 'https://github.com/ccrisan/motioneye/issues/2292'}, {'type': 'WEB', 'url': 'https://github.com/motioneye-project/motioneye/commit/c60b64af5bb8c09189071522a1f6796cb44340b0'}, {'type': 'PACKAGE', 'url': 'https://github.com/motioneye-project/motioneye'}, {'type': 'WEB', 'url': 'https://github.com/pypa/advisory-database/tree/main/vulns/motioneye/PYSEC-2022-43141.yaml'}, {'type': 'WEB', 'url': 'https://www.pizzapower.me/2022/02/17/motioneye-config-info-disclosure'}], 'database_specific': {'cwe_ids': ['CWE-200'], 'severity': 'HIGH', 'github_reviewed': True, 'github_reviewed_at': '2024-11-22T20:20:55Z', 'nvd_published_at': '2022-03-24T17:15:00Z'}}]})
    '''
    return classified

def write_advisories_to_files(classified, output_dir="advisories"):
    os.makedirs(output_dir, exist_ok=True)
    for severity, items in classified.items():
        severity_dir = os.path.join(output_dir, severity)
        os.makedirs(severity_dir, exist_ok=True) #True flag for if the dir already exists
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
            continue  # Only process if it's a sub-directory
        
        zip_filename = os.path.join(output_dir, f"{severity}.zip")
        
        # Create a zip file for each severity folder
        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
            # Walk through the severity folder
            for root, _, files in os.walk(severity_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    #To preserve the directory structure within the zip file. For example, if a file is located at advisories/high/CVE-2023-123.json, the arcname might be high/CVE-2023-123.json within the zip file.
                    arcname = os.path.relpath(file_path, input_dir)  # Preserve relative path
                    zipf.write(file_path, arcname)
                    
        print(f"✅ Created: {zip_filename}")

def fetch_kev_cves():
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    try:
        response = requests.get(kev_url)
        response.raise_for_status()
        kev_data = response.json()
        #This is a set, not a dict  
        #ALso, this set() will only have unique CVE's
        kev_cves = {
            item["cveID"]
            for item in kev_data.get("vulnerabilities", [])
            if "cveID" in item #prevent checking for a non-existent key
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
                #Sometimes, aliases will be empty, sometimes 
                #it'll have a CVE-ID, sometimes it'll have multiple
                #We are only interested in the first CVE-ID
                cve_id = aliases[0] if aliases else ""
                summary = adv.get("summary", "")
                package = ""
                ecosystem = ""

                if adv.get("affected"):
                    '''
                    "affected": [
                    {
                    "package": {
                        "ecosystem": "Go",
                        "name": "github.com/grafana/grafana-plugin-sdk-go"
                    },
                    "ranges": [
                        {
                        "type": "ECOSYSTEM",
                        "events": [
                            {
                            "introduced": "0"
                            },
                            {
                            "fixed": "0.250.0"
                            }
                        ]
                        }
                    ],
                    '''
                    #extract the first item in the list
                    pkg = adv["affected"][0].get("package", {})
                    #Then extract the name of the package
                    #as it's the second key in the package dict
                    package = pkg.get("name", "")
                    ecosystem = pkg.get("ecosystem", "")
                
                kev = "1" if cve_id in kev_set else ""
                #write a new row for the extracted info
                writer.writerow([ghsa_id, cve_id, severity.upper(), package, ecosystem, summary, kev])


if __name__ == "__main__":
    main()

