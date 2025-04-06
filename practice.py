import os
import json
from collections import defaultdict
import zipfile
import csv
import requests

def main():
    #load advisories
    advisories = load_advisories("advisory-database/advisories/github-reviewed")
    print(f"✅ Loaded {len(advisories)} advisories.")
    
    #classify by severity
    classified = classify_by_severity(advisories)
    for severity, items in classified.items():
        print(f"📦 {severity.upper()}: {len(items)} advisories")
    #write advisories to 4 folders, by severity i.e. 
    # CRITICAL, HIGH, MODERATE, LOW
    
    #fetch KEV info
    
    #generate CSV report with KEV flag
    
def load_advisories(base_path):
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
    print(type(advisories))
    print(len(advisories))
    return advisories
 
 
def classify_by_severity(advisories):
    print(advisories[0])
    classified = defaultdict(list)
    for adv in advisories:
        severity = adv.get("database_specific", {}).get("severity", "UNKNOWN").lower()
        classified[severity].append(adv)
    return classified

def zip_four_folders(input_dir="", output_dir=""):
    ...
    return

def fetch_kev_cves():
    return kev_cves

def write_csv(classified, kev_cves, output_file="advisories.csv"):
    return
    
if __name__ == "__main__":
    main()


